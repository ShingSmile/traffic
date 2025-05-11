import os
import numpy as np
import argparse
import time
import random
import csv
from scapy.all import PcapReader, IP, TCP, UDP, wrpcap

class PCAPFlowExtractor:
    """PCAP文件流量提取工具 - 可选择单向/双向流量，专为SSH流量和HMSFW水印系统设计"""
    
    def __init__(self):
        """初始化提取器"""
        self.flows = {}  # 存储所有流的字典: {flow_key: {'packets': [], 'direction': src_endpoint}}
        self.pcap_file = None
        self.total_packets = 0
        self.processed_packets = 0
        
    def process_pcap(self, pcap_file, max_flows=128, min_packets=10, max_scan_packets=None, 
                     payload_only=True, min_interval_ms=0.1, max_interval_ms=1000, 
                     unidirectional=True, ssh_only=True):
        """扫描PCAP文件并识别满足条件的流，直到找到足够数量的流
        
        参数:
            pcap_file: PCAP文件路径
            max_flows: 需要提取的最大流数量，默认为128
            min_packets: 每个流至少需要的过滤后数据包数量，默认为10
            max_scan_packets: 最大扫描的数据包数量，None表示无限制
            payload_only: 是否只考虑有效负载的数据包，默认为True
            min_interval_ms: 最小间隔(毫秒)，小于此值的间隔将被过滤掉，默认为0.1ms
            max_interval_ms: 最大间隔(毫秒)，大于此值的间隔将被过滤掉，默认为1000ms
            unidirectional: 是否只提取单向流，默认为True
            ssh_only: 是否只关注SSH流量，默认为True
        """
        self.pcap_file = pcap_file
        self.flows = {}
        
        flow_type = "单向" if unidirectional else "双向"
        protocol_type = "SSH流量" if ssh_only else "所有TCP/UDP流量"
        
        print(f"处理PCAP文件: {pcap_file}...")
        print(f"目标: 提取 {max_flows} 个{flow_type}流，每个流至少 {min_packets} 个有效数据包")
        print(f"过滤条件: {protocol_type}, 有效负载={payload_only}, 时间间隔={min_interval_ms}ms~{max_interval_ms}ms")
        
        try:
            start_time = time.time()
            last_update = start_time
            update_interval = 2.0  # 进度更新间隔(秒)
            
            # 使用PcapReader进行流式读取
            with PcapReader(pcap_file) as pcap_reader:
                self.processed_packets = 0
                
                for packet in pcap_reader:
                    self.processed_packets += 1
                    
                    # 进度显示
                    current_time = time.time()
                    if current_time - last_update > update_interval:
                        elapsed = current_time - start_time
                        rate = self.processed_packets / elapsed if elapsed > 0 else 0
                        print(f"\r已处理 {self.processed_packets} 个数据包，"
                              f"处理速度: {rate:.2f} 包/秒，"
                              f"发现 {len(self.flows)} 个流", end="")
                        last_update = current_time
                    
                    # 处理数据包
                    self._process_packet(packet, unidirectional=unidirectional, ssh_only=ssh_only)
                    
                    # 如果已经找到足够多的合格流，提前退出
                    qualified_flows = self._get_qualified_flows(min_packets, min_interval_ms, 
                                                               max_interval_ms, payload_only)
                    if len(qualified_flows) >= max_flows:
                        print(f"\n已找到 {len(qualified_flows)} 个合格流，满足条件，提前结束扫描")
                        break
                    
                    # 达到最大扫描包数限制时退出
                    if max_scan_packets and self.processed_packets >= max_scan_packets:
                        print(f"\n已达到最大扫描包数 {max_scan_packets}，结束扫描")
                        break
            
            self.total_packets = self.processed_packets
            elapsed = time.time() - start_time
            rate = self.processed_packets / elapsed if elapsed > 0 else 0
            
            print(f"\n完成! 耗时: {elapsed:.2f}秒, 共扫描 {self.processed_packets} 个数据包, "
                  f"速度: {rate:.2f}包/秒")
            
            # 获取合格的流
            qualified_flows = self._get_qualified_flows(min_packets, min_interval_ms, 
                                                       max_interval_ms, payload_only)
            print(f"共发现 {len(qualified_flows)} 个合格{flow_type}流 (每个流至少 {min_packets} 个符合条件的数据包)")
            
            return True
            
        except Exception as e:
            print(f"\n处理PCAP文件失败: {str(e)}")
            return False
    
    def _process_packet(self, packet, unidirectional=True, ssh_only=True):
        """处理单个数据包并将其添加到相应的流中"""
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                if TCP in packet:
                    proto = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    
                    # 检查是否是SSH流量 (端口22)
                    is_ssh = (sport == 22 or dport == 22)
                    if ssh_only and not is_ssh:
                        return  # 只关注SSH流量
                    
                    # 检查是否有负载
                    has_payload = False
                    if hasattr(packet[TCP], 'payload') and len(packet[TCP].payload) > 0:
                        has_payload = True
                    
                elif UDP in packet:
                    proto = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    
                    # 检查是否是SSH流量 (端口22)
                    is_ssh = (sport == 22 or dport == 22)
                    if ssh_only and not is_ssh:
                        return  # 只关注SSH流量
                    
                    # 检查是否有负载
                    has_payload = False
                    if hasattr(packet[UDP], 'payload') and len(packet[UDP].payload) > 0:
                        has_payload = True
                    
                else:
                    return  # 忽略非TCP/UDP流量
                
                # 源和目的端点
                src_endpoint = f"{ip_src}:{sport}"
                dst_endpoint = f"{ip_dst}:{dport}"
                
                # 单双向流处理逻辑区分
                if unidirectional:
                    # 单向流标识 - 使用五元组唯一标识
                    flow_key = f"{ip_src}:{sport}-{ip_dst}:{dport}-{proto}"
                    
                    # 初始化流信息
                    if flow_key not in self.flows:
                        self.flows[flow_key] = {
                            'packets': [],
                            'direction': src_endpoint,
                            'has_payload': []  # 记录每个包是否有负载
                        }
                    
                    # 确保数据包方向与流的初始方向一致（单向性检查）
                    packet_src = src_endpoint
                    if self.flows[flow_key]['direction'] == packet_src:
                        # 将数据包添加到流中
                        self.flows[flow_key]['packets'].append(packet)
                        self.flows[flow_key]['has_payload'].append(has_payload)
                
                else:
                    # 双向流处理 - 使用四元组标识，忽略方向
                    # 确保源和目标总是按照特定顺序排列（小的在前）
                    if f"{ip_src}:{sport}" < f"{ip_dst}:{dport}":
                        flow_key = f"{ip_src}:{sport}<->{ip_dst}:{dport}-{proto}"
                    else:
                        flow_key = f"{ip_dst}:{dport}<->{ip_src}:{sport}-{proto}"
                    
                    # 初始化流信息
                    if flow_key not in self.flows:
                        self.flows[flow_key] = {
                            'packets': [],
                            'directions': {src_endpoint, dst_endpoint},  # 使用集合记录双向
                            'has_payload': []  # 记录每个包是否有负载
                        }
                    
                    # 双向流，记录数据包的方向
                    packet_direction = src_endpoint
                    # 将数据包添加到流中
                    self.flows[flow_key]['packets'].append(packet)
                    self.flows[flow_key]['has_payload'].append(has_payload)
                
        except Exception as e:
            # 忽略处理错误的数据包
            pass
    
    def _get_qualified_flows(self, min_packets, min_interval_ms=0.1, max_interval_ms=1000, payload_only=True):
        """获取满足过滤条件的流
        
        参数:
            min_packets: 每个流至少需要的有效数据包数量
            min_interval_ms: 最小间隔(毫秒)
            max_interval_ms: 最大间隔(毫秒)
            payload_only: 是否只考虑有效负载的数据包
        """
        qualified_flows = {}
        
        for flow_key, flow_data in self.flows.items():
            packets = flow_data['packets']
            has_payload = flow_data['has_payload']
            
            # 根据payload_only参数决定是否过滤没有负载的数据包
            if payload_only:
                filtered_packets = [p for i, p in enumerate(packets) if has_payload[i]]
            else:
                filtered_packets = packets
            
            # 如果过滤后的包数量不足，跳过
            if len(filtered_packets) < min_packets:
                continue
            
            # 提取时间戳并排序
            timestamps = [float(p.time) for p in filtered_packets]
            timestamps.sort()
            
            # 计算时间间隔(毫秒)
            intervals = [(timestamps[i+1] - timestamps[i]) * 1000 for i in range(len(timestamps)-1)]
            
            # 过滤不符合时间间隔条件的间隔
            valid_intervals = [
                interval for interval in intervals 
                if min_interval_ms <= interval <= max_interval_ms
            ]
            
            # 计算有效数据包数量 (基于有效间隔+1)
            valid_packet_count = len(valid_intervals) + 1 if valid_intervals else 0
            
            # 只选择有足够多有效数据包的流
            if valid_packet_count >= min_packets:
                qualified_flows[flow_key] = {
                    'packets': filtered_packets,
                    'all_packets': packets,  # 保留所有包供参考
                    'timestamps': timestamps,
                    'intervals': intervals,
                    'valid_intervals': valid_intervals,
                    'valid_packet_count': valid_packet_count
                }
        
        return qualified_flows
    
    def print_flows(self, min_packets=10, min_interval_ms=0.1, max_interval_ms=1000, 
                    payload_only=True, top_n=128, unidirectional=True):
        """打印发现的符合条件的流信息"""
        flow_type = "单向" if unidirectional else "双向"
        qualified_flows = self._get_qualified_flows(min_packets, min_interval_ms, 
                                                   max_interval_ms, payload_only)
        
        if not qualified_flows:
            print("未发现符合条件的流，请先处理PCAP文件")
            return
        
        print(f"\n{'='*80}")
        print(f"PCAP文件中的合格{flow_type}流 (每个流至少 {min_packets} 个有效数据包, "
              f"间隔: {min_interval_ms}~{max_interval_ms}ms, 有效负载: {payload_only}):")
        print(f"{'='*80}")
        print(f"{'#':<4} {'流标识':<50} {'原始/有效/有效间隔':<20} {'持续时间(秒)':<15}")
        print(f"{'-'*80}")
        
        # 按有效数据包数量降序排序
        sorted_flows = sorted(
            qualified_flows.items(), 
            key=lambda item: item[1]['valid_packet_count'], 
            reverse=True
        )
        
        for i, (flow_key, flow_data) in enumerate(sorted_flows[:top_n]):
            packets = flow_data['packets']
            all_packets = flow_data['all_packets']
            valid_intervals = flow_data['valid_intervals']
            
            # 计算流持续时间
            start_time = min(float(p.time) for p in packets)
            end_time = max(float(p.time) for p in packets)
            duration = end_time - start_time
            
            # 显示三个数量: 原始包数/过滤后的包数/有效间隔数
            counts = f"{len(all_packets)}/{len(packets)}/{len(valid_intervals)}"
            
            print(f"{i:<4} {flow_key:<50} {counts:<20} {duration:.2f}")
    
    def extract_time_intervals(self, flow_key, flow_data, min_interval_ms=0.1, max_interval_ms=1000):
        """提取指定流的有效时间间隔
        
        参数:
            flow_key: 流标识
            flow_data: 流数据
            min_interval_ms: 最小间隔(毫秒)
            max_interval_ms: 最大间隔(毫秒)
            
        返回:
            有效时间间隔列表(毫秒)
        """
        if 'valid_intervals' in flow_data:
            intervals = flow_data['valid_intervals']
        else:
            # 如果没有预先计算，则计算有效间隔
            intervals = flow_data['intervals']
            intervals = [
                interval for interval in intervals 
                if min_interval_ms <= interval <= max_interval_ms
            ]
        
        # 计算并打印统计信息
        if intervals:
            min_val = min(intervals)
            max_val = max(intervals)
            avg_val = sum(intervals) / len(intervals)
            print(f"流 {flow_key} 的间隔统计 (有效间隔={len(intervals)}):")
            print(f"  最小: {min_val:.3f}ms, 最大: {max_val:.3f}ms, 平均: {avg_val:.3f}ms")
        else:
            print(f"流 {flow_key} 没有有效的时间间隔")
        
        return intervals
    
    def save_intervals_to_csv(self, intervals, output_file):
        """将时间间隔保存到CSV文件"""
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["interval_ms"])
                for interval in intervals:
                    writer.writerow([interval])
            return True
        except Exception as e:
            print(f"保存时间间隔失败: {str(e)}")
            return False
    
    def extract_random_flows(self, output_dir, num_flows=128, min_packets=10, 
                            min_interval_ms=0.1, max_interval_ms=1000,
                            save_pcap=True, save_intervals=True, 
                            payload_only=True, unidirectional=True):
        """随机提取指定数量的符合条件的流并保存
        
        参数:
            output_dir: 输出目录
            num_flows: 要提取的流数量
            min_packets: 每个流至少需要的有效数据包数量
            min_interval_ms: 最小间隔(毫秒)
            max_interval_ms: 最大间隔(毫秒)
            save_pcap: 是否保存PCAP文件
            save_intervals: 是否保存时间间隔到CSV
            payload_only: 是否只考虑有效负载的数据包
            unidirectional: 是否只提取单向流
        
        返回:
            提取的流标识列表
        """
        flow_type = "单向" if unidirectional else "双向"
        qualified_flows = self._get_qualified_flows(min_packets, min_interval_ms, 
                                                   max_interval_ms, payload_only)
        
        if not qualified_flows:
            print("未发现符合条件的流，请先处理PCAP文件")
            return []
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        if save_intervals:
            intervals_dir = os.path.join(output_dir, "intervals")
            os.makedirs(intervals_dir, exist_ok=True)
        
        # 随机选择流
        flow_keys = list(qualified_flows.keys())
        if len(flow_keys) <= num_flows:
            selected_keys = flow_keys
            print(f"警告: 只找到 {len(flow_keys)} 个合格流，少于请求的 {num_flows} 个")
        else:
            selected_keys = random.sample(flow_keys, num_flows)
        
        print(f"\n将随机提取 {len(selected_keys)} 个{flow_type}流并保存到 {output_dir} 目录")
        print(f"流过滤条件: {'有效负载' if payload_only else '所有数据包'}, 时间间隔 {min_interval_ms}~{max_interval_ms}ms，"
              f"每个流至少 {min_packets} 个有效数据包")
        
        extracted_flows = []
        for i, flow_key in enumerate(selected_keys):
            try:
                safe_name = flow_key.replace(":", "_").replace("-", "_").replace("<->", "_to_")
                base_filename = f"flow_{i:03d}_{safe_name}"
                flow_data = qualified_flows[flow_key]
                packets = flow_data['packets']  # 已经过滤的数据包
                
                output = {}
                
                # 保存PCAP文件
                if save_pcap:
                    pcap_file = os.path.join(output_dir, f"{base_filename}.pcap")
                    wrpcap(pcap_file, packets)
                    output["pcap"] = pcap_file
                
                # 提取并保存时间间隔
                if save_intervals:
                    intervals = self.extract_time_intervals(
                        flow_key, flow_data, min_interval_ms, max_interval_ms)
                    
                    # 统计间隔数据
                    if intervals:
                        # 计算间隔的统计信息
                        min_interval = min(intervals) if intervals else 0
                        max_interval = max(intervals) if intervals else 0
                        avg_interval = np.mean(intervals) if intervals else 0
                        
                        # 保存到CSV
                        intervals_file = os.path.join(intervals_dir, f"{base_filename}.csv")
                        self.save_intervals_to_csv(intervals, intervals_file)
                        
                        # 保存到输出信息
                        output["intervals"] = intervals_file
                        output["intervals_count"] = len(intervals)
                        output["min_interval"] = min_interval
                        output["max_interval"] = max_interval
                        output["avg_interval"] = avg_interval
                
                # 生成一个统一的输出描述
                outputs = []
                if save_pcap:
                    outputs.append("PCAP")
                if save_intervals:
                    outputs.append(f"间隔CSV({len(intervals) if 'intervals_count' in output else 0}个)")
                
                print(f"流 {i:03d}: {flow_key} - 有效数据包:{len(packets)} -> {', '.join(outputs)}")
                
                extracted_flows.append({
                    "index": i,
                    "key": flow_key,
                    "valid_packets": len(packets),
                    "all_packets": len(flow_data['all_packets']),
                    **output
                })
            except Exception as e:
                print(f"处理流 {flow_key} 失败: {str(e)}")
        
        print(f"\n成功提取 {len(extracted_flows)} 个流到 {output_dir}")
        return extracted_flows


def main():
    """主函数 - 流提取版本"""
    parser = argparse.ArgumentParser(description="PCAP流量提取与时间间隔分析工具")
    parser.add_argument("pcap_file", help="要处理的PCAP文件路径")
    parser.add_argument("--output-dir", "-o", help="输出目录，默认为'extracted_flows'", 
                      default="extracted_flows")
    parser.add_argument("--num-flows", "-n", type=int, help="要提取的流数量，默认为128", default=128)
    parser.add_argument("--min-packets", "-p", type=int, help="每个流至少需要的有效数据包数量，默认为10", default=10)
    parser.add_argument("--max-scan", "-m", type=int, help="最大扫描的数据包数量，默认无限制")
    parser.add_argument("--list-only", "-l", action="store_true", help="只列出流信息后退出，不提取")
    parser.add_argument("--save-pcap", "-s", action="store_true", help="保存提取的流为PCAP文件", default=False)
    parser.add_argument("--min-interval", type=float, help="最小间隔(毫秒)，默认为0.1ms", default=0.1)
    parser.add_argument("--max-interval", type=float, help="最大间隔(毫秒)，默认为1000ms", default=1000.0)
    parser.add_argument("--bidirectional", "-b", action="store_true", 
                        help="提取双向流而非单向流，默认为False（单向流）")
    parser.add_argument("--all-packets", "-a", action="store_true", 
                        help="包含所有数据包，不仅限于有效负载的包，默认为False（仅有效负载包）")
    parser.add_argument("--all-protocols", "-ap", action="store_true", 
                        help="提取所有TCP/UDP流量，不仅限于SSH流量，默认为False（仅SSH流量）")
    
    args = parser.parse_args()
    
    flow_type = "双向" if args.bidirectional else "单向"
    packet_type = "所有" if args.all_packets else "有效负载"
    protocol_type = "所有TCP/UDP流量" if args.all_protocols else "SSH流量"
    
    print("\n=== PCAP流量分析工具 ===")
    print(f"过滤条件: {flow_type}流, {packet_type}数据包, {protocol_type}, 时间间隔 {args.min_interval}~{args.max_interval}ms")
    
    # 创建提取器
    extractor = PCAPFlowExtractor()
    
    # 处理PCAP文件
    if not extractor.process_pcap(
        args.pcap_file, 
        args.num_flows, 
        args.min_packets, 
        args.max_scan,
        payload_only=not args.all_packets, 
        min_interval_ms=args.min_interval,
        max_interval_ms=args.max_interval,
        unidirectional=not args.bidirectional,
        ssh_only=not args.all_protocols
    ):
        return
    
    # 打印流信息
    extractor.print_flows(
        args.min_packets, 
        args.min_interval, 
        args.max_interval, 
        payload_only=not args.all_packets,
        unidirectional=not args.bidirectional
    )
    
    # 如果只需列出流，则退出
    if args.list_only:
        return
    
    # 提取随机流并保存
    extractor.extract_random_flows(
        output_dir=args.output_dir,
        num_flows=args.num_flows,
        min_packets=args.min_packets,
        min_interval_ms=args.min_interval,
        max_interval_ms=args.max_interval,
        save_pcap=args.save_pcap,
        save_intervals=True,
        payload_only=not args.all_packets,
        unidirectional=not args.bidirectional
    )


if __name__ == "__main__":
    main()
