import os
import numpy as np
import argparse
import time
import random
import csv
from scapy.all import PcapReader, IP, TCP, UDP

class PCAPFlowExtractor:
    """PCAP文件流量提取工具 - 针对SSH流量优化的高性能版本"""
    
    def __init__(self):
        """初始化提取器"""
        self.flows = {}  # 存储所有流的字典: {flow_key: {'packets_info': [], 'direction': src_endpoint}}
        self.pcap_file = None
        self.total_packets = 0
        self.processed_packets = 0
        
    def process_pcap(self, pcap_file, max_flows=128, min_packets=10, max_scan_packets=None, 
                     payload_only=True, min_interval_ms=0.1, max_interval_ms=1000):
        """扫描PCAP文件并识别满足条件的流
        
        参数:
            pcap_file: PCAP文件路径
            max_flows: 需要提取的最大流数量，默认为128
            min_packets: 每个流至少需要的过滤后数据包数量，默认为10
            max_scan_packets: 最大扫描的数据包数量，None表示无限制
            payload_only: 是否只考虑有效负载的数据包，默认为True
            min_interval_ms: 最小间隔(毫秒)，小于此值的间隔将被过滤掉，默认为0.1ms
            max_interval_ms: 最大间隔(毫秒)，大于此值的间隔将被过滤掉，默认为1000ms
        """
        self.pcap_file = pcap_file
        self.flows = {}
        
        print(f"处理PCAP文件: {pcap_file}...")
        print(f"目标: 提取 {max_flows} 个单向流，每个流至少 {min_packets} 个有效数据包")
        print(f"过滤条件: SSH流量, 有效负载={payload_only}, 时间间隔={min_interval_ms}ms~{max_interval_ms}ms")
        
        try:
            start_time = time.time()
            last_update = start_time
            last_memory_check = start_time
            update_interval = 2.0  # 进度更新间隔(秒)
            memory_check_interval = 10.0  # 内存检查间隔(秒)
            
            # 定期清理缓存变量
            qualified_flows_count = 0
            last_qualified_check = 0
            check_qualified_every = 10000  # 每处理这么多包检查一次合格流数量
            
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
                        
                        # 获取合格流数量（不频繁检查，以提高性能）
                        if self.processed_packets - last_qualified_check >= check_qualified_every:
                            qualified_flows = self._get_qualified_flows_count(min_packets, min_interval_ms, 
                                                                         max_interval_ms, payload_only)
                            qualified_flows_count = qualified_flows
                            last_qualified_check = self.processed_packets
                        
                        print(f"\r已处理 {self.processed_packets} 个数据包，"
                              f"处理速度: {rate:.2f} 包/秒，"
                              f"发现 {len(self.flows)} 个流，"
                              f"合格流: {qualified_flows_count} 个", end="")
                        last_update = current_time
                    
                    # 处理数据包
                    self._process_packet_optimized(packet, payload_only)
                    
                    # 定期检查是否找到足够多的合格流
                    if self.processed_packets - last_qualified_check >= check_qualified_every:
                        qualified_flows_count = self._get_qualified_flows_count(min_packets, min_interval_ms, 
                                                                         max_interval_ms, payload_only)
                        last_qualified_check = self.processed_packets
                        
                        # 如果已经找到足够多的合格流，提前退出
                        if qualified_flows_count >= max_flows:
                            print(f"\n已找到 {qualified_flows_count} 个合格流，满足条件，提前结束扫描")
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
            
            # 获取合格的流数量
            qualified_flows_count = self._get_qualified_flows_count(min_packets, min_interval_ms, 
                                                           max_interval_ms, payload_only)
            print(f"共发现 {qualified_flows_count} 个合格单向流 (每个流至少 {min_packets} 个符合条件的数据包)")
            
            return True
            
        except Exception as e:
            print(f"\n处理PCAP文件失败: {str(e)}")
            return False
    
    def _process_packet_optimized(self, packet, payload_only=True):
        """优化的数据包处理方法 - 只存储必要信息而非整个数据包"""
        try:
            if IP in packet and TCP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                
                # 只处理SSH流量 (端口22)
                if sport != 22 and dport != 22:
                    return
                
                # 确定数据包是否有载荷
                has_payload = bool(hasattr(packet[TCP], 'payload') and len(packet[TCP].payload) > 0)
                
                # 如果只处理有载荷的包，且这个包没有载荷，则跳过
                if payload_only and not has_payload:
                    return
                
                # 源端点
                src_endpoint = f"{ip_src}:{sport}"
                
                # 单向流标识
                flow_key = f"{ip_src}:{sport}-{ip_dst}:{dport}-TCP"
                
                # 初始化流信息(只在需要时初始化)
                if flow_key not in self.flows:
                    self.flows[flow_key] = {
                        'packets_info': [],  # 只存储必要的信息，不存储完整数据包
                        'direction': src_endpoint
                    }
                
                # 确保数据包方向与流的初始方向一致（单向性检查）
                packet_src = src_endpoint
                if self.flows[flow_key]['direction'] == packet_src:
                    # 只存储必要的信息
                    self.flows[flow_key]['packets_info'].append({
                        'time': float(packet.time),
                        'has_payload': has_payload
                    })
                
        except Exception as e:
            # 忽略处理错误的数据包
            pass
    
    def _get_qualified_flows_count(self, min_packets, min_interval_ms=0.1, max_interval_ms=1000, payload_only=True):
        """获取符合条件的流数量 - 性能优化版本"""
        count = 0
        
        for flow_key, flow_data in self.flows.items():
            packets_info = flow_data['packets_info']
            
            # 如果包数量不够最低要求，快速跳过
            if len(packets_info) < min_packets:
                continue
                
            # 提取时间戳并排序
            timestamps = [p['time'] for p in packets_info]
            timestamps.sort()
            
            # 计算时间间隔(毫秒)
            intervals = [(timestamps[i+1] - timestamps[i]) * 1000 for i in range(len(timestamps)-1)]
            
            # 快速计算有效间隔数量
            valid_interval_count = sum(1 for interval in intervals 
                                    if min_interval_ms <= interval <= max_interval_ms)
            
            # 计算有效数据包数量 (基于有效间隔+1)
            valid_packet_count = valid_interval_count + 1 if valid_interval_count else 0
            
            # 只选择有足够多有效数据包的流
            if valid_packet_count >= min_packets:
                count += 1
        
        return count
    
    def _get_qualified_flows(self, min_packets, min_interval_ms=0.1, max_interval_ms=1000, payload_only=True):
        """获取满足过滤条件的流 - 优化版本"""
        qualified_flows = {}
        
        for flow_key, flow_data in self.flows.items():
            packets_info = flow_data['packets_info']
            
            # 如果包数量不够最低要求，快速跳过
            if len(packets_info) < min_packets:
                continue
            
            # 提取时间戳并排序
            timestamps = [p['time'] for p in packets_info]
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
                    'packets_info': packets_info,
                    'timestamps': timestamps,
                    'intervals': intervals,
                    'valid_intervals': valid_intervals,
                    'valid_packet_count': valid_packet_count
                }
        
        return qualified_flows
    
    def print_flows(self, min_packets=10, min_interval_ms=0.1, max_interval_ms=1000, 
                    payload_only=True, top_n=128):
        """打印发现的符合条件的流信息"""
        qualified_flows = self._get_qualified_flows(min_packets, min_interval_ms, 
                                                   max_interval_ms, payload_only)
        
        if not qualified_flows:
            print("未发现符合条件的流，请先处理PCAP文件")
            return
        
        print(f"\n{'='*80}")
        print(f"PCAP文件中的合格单向流 (每个流至少 {min_packets} 个有效数据包, "
              f"间隔: {min_interval_ms}~{max_interval_ms}ms, 有效负载: {payload_only}):")
        print(f"{'='*80}")
        print(f"{'#':<4} {'流标识':<50} {'原始/有效间隔':<20} {'持续时间(秒)':<15}")
        print(f"{'-'*80}")
        
        # 按有效数据包数量降序排序
        sorted_flows = sorted(
            qualified_flows.items(), 
            key=lambda item: item[1]['valid_packet_count'], 
            reverse=True
        )
        
        for i, (flow_key, flow_data) in enumerate(sorted_flows[:top_n]):
            packets_info = flow_data['packets_info']
            valid_intervals = flow_data['valid_intervals']
            
            # 计算流持续时间
            timestamps = [p['time'] for p in packets_info]
            start_time = min(timestamps)
            end_time = max(timestamps)
            duration = end_time - start_time
            
            # 显示信息: 包数/有效间隔数
            counts = f"{len(packets_info)}/{len(valid_intervals)}"
            
            print(f"{i:<4} {flow_key:<50} {counts:<20} {duration:.2f}")
    
    def extract_time_intervals(self, flow_key, flow_data, min_interval_ms=0.1, max_interval_ms=1000):
        """提取指定流的有效时间间隔"""
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
    
    def extract_flows(self, output_dir, min_packets=10, 
                     min_interval_ms=0.1, max_interval_ms=1000,
                     save_intervals=True, payload_only=True):
        """提取所有符合条件的流并保存间隔
        
        参数:
            output_dir: 输出目录
            min_packets: 每个流至少需要的有效数据包数量
            min_interval_ms: 最小间隔(毫秒)
            max_interval_ms: 最大间隔(毫秒)
            save_intervals: 是否保存时间间隔到CSV
            payload_only: 是否只考虑有效负载的数据包
        
        返回:
            提取的流标识列表
        """
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
        
        flow_keys = list(qualified_flows.keys())
        print(f"\n将提取 {len(flow_keys)} 个合格单向流并保存到 {output_dir} 目录")
        print(f"流过滤条件: {'有效负载' if payload_only else '所有数据包'}, 时间间隔 {min_interval_ms}~{max_interval_ms}ms，"
              f"每个流至少 {min_packets} 个有效数据包")
        
        extracted_flows = []
        for i, flow_key in enumerate(flow_keys):
            try:
                safe_name = flow_key.replace(":", "_").replace("-", "_").replace("<->", "_to_")
                base_filename = f"flow_{i:03d}_{safe_name}"
                flow_data = qualified_flows[flow_key]
                
                output = {}
                
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
                if save_intervals:
                    outputs.append(f"间隔CSV({len(intervals) if 'intervals_count' in output else 0}个)")
                
                valid_packets = flow_data.get('valid_packet_count', 0)
                packets_count = len(flow_data.get('packets_info', []))
                
                print(f"流 {i:03d}: {flow_key} - 包:{packets_count}, 有效:{valid_packets} -> {', '.join(outputs)}")
                
                extracted_flows.append({
                    "index": i,
                    "key": flow_key,
                    "valid_packets": valid_packets,
                    "packets_count": packets_count,
                    **output
                })
            except Exception as e:
                print(f"处理流 {flow_key} 失败: {str(e)}")
        
        print(f"\n成功提取 {len(extracted_flows)} 个流到 {output_dir}")
        return extracted_flows


def main():
    """主函数 - 流提取优化版本"""
    parser = argparse.ArgumentParser(description="优化版PCAP流量提取与时间间隔分析工具")
    parser.add_argument("pcap_file", help="要处理的PCAP文件路径")
    parser.add_argument("--output-dir", "-o", help="输出目录，默认为'extracted_flows'", 
                      default="extracted_flows")
    parser.add_argument("--num-flows", "-n", type=int, help="要提取的流数量，默认为128", default=128)
    parser.add_argument("--min-packets", "-p", type=int, help="每个流至少需要的有效数据包数量，默认为10", default=10)
    parser.add_argument("--max-scan", "-m", type=int, help="最大扫描的数据包数量，默认无限制")
    parser.add_argument("--list-only", "-l", action="store_true", help="只列出流信息后退出，不提取")
    parser.add_argument("--min-interval", type=float, help="最小间隔(毫秒)，默认为0.1ms", default=0.1)
    parser.add_argument("--max-interval", type=float, help="最大间隔(毫秒)，默认为1000ms", default=1000.0)
    parser.add_argument("--all-packets", "-a", action="store_true", 
                        help="包含所有数据包，不仅限于有效负载的包，默认为False（仅有效负载包）")
    
    args = parser.parse_args()
    
    packet_type = "所有" if args.all_packets else "有效负载"
    
    print("\n=== 优化版PCAP流量分析工具 ===")
    print(f"过滤条件: 单向流, {packet_type}数据包, SSH流量, 时间间隔 {args.min_interval}~{args.max_interval}ms")
    
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
        max_interval_ms=args.max_interval
    ):
        return
    
    # 打印流信息
    extractor.print_flows(
        args.min_packets, 
        args.min_interval, 
        args.max_interval, 
        payload_only=not args.all_packets
    )
    
    # 如果只需列出流，则退出
    if args.list_only:
        return
    
    # 提取所有符合条件的流并保存
    extractor.extract_flows(
        output_dir=args.output_dir,
        min_packets=args.min_packets,
        min_interval_ms=args.min_interval,
        max_interval_ms=args.max_interval,
        save_intervals=True,
        payload_only=not args.all_packets
    )


if __name__ == "__main__":
    main()