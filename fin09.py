import socket
import threading
import ipaddress

# TCP连接
def tcpConnScan(tgtHost, tgtPort):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((tgtHost, tgtPort))
        print(' [+] %d/tcp open \n' % tgtPort)
    except socket.gaierror:
        print("[-] 无法解析目标主机: %s" % tgtHost)
    except Exception as err:
        print(' [-] %d/tcp closed\n' % tgtPort)
    finally:
        conn.close()

# UDP连接
def udpConnScan(tgtHost, tgtPort):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(1)
        conn.sendto(b'123', (tgtHost, tgtPort))
        data, addr = conn.recvfrom(1024)
        print(' [+] %d/udp open \n' % tgtPort)
    except socket.gaierror:
        print("[-] 无法解析目标主机: %s" % tgtHost)
    except Exception as err:
        print(' [-] %d/udp closed\n' % tgtPort)
    finally:
        conn.close()

# 端口扫描
def portScan(tgtHost, tgtPorts, scanType):
    try:
        tgtIP = socket.gethostbyname(tgtHost)
        print("[+] Scan Results for: " + tgtIP)
    except:
        print("[-] 无法解析 '%s': 未知主机" % tgtHost)
        return
    socket.setdefaulttimeout(1)
    threads = []
    for port in tgtPorts:
        if '-' in port:
            start_port, end_port = map(int, port.split('-'))
            for tgtPort in range(start_port, end_port + 1):
                if scanType == "TCP":
                    t = threading.Thread(target=tcpConnScan, args=(tgtHost, tgtPort))
                elif scanType == "UDP":
                    t = threading.Thread(target=udpConnScan, args=(tgtHost, tgtPort))
                else:
                    print("[-] 无效的扫描类型: %s" % scanType)
                    return
                threads.append(t)
                t.start()
        else:
            tgtPort = int(port)
            if scanType == "TCP":
                t = threading.Thread(target=tcpConnScan, args=(tgtHost, tgtPort))
            elif scanType == "UDP":
                t = threading.Thread(target=udpConnScan, args=(tgtHost, tgtPort))
            else:
                print("[-] 无效的扫描类型: %s" % scanType)
                return
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

def main():
    scanType = input("选择扫描类型 (TCP or UDP): ")
    scanObj = input("选择扫描对象 (single, cidr or iprange): ")
    if scanObj.lower() == "single":
        tgtHost = input("输入目标主机 IP 地址: ")
        tgtPorts_str = input("输入用逗号分隔的目标端口号或用连字符分隔的连续目标端口段: ")
        tgtPorts = tgtPorts_str.split(",")
        portScan(tgtHost, tgtPorts, scanType.upper())
    elif scanObj.lower() == "cidr":
        cidr = input("输入 CIDR 地址块: ")
        try:
            subnet = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            print("无效的 CIDR 地址块.")
            return
        tgtPorts_str = input("输入用逗号分隔的目标端口号或用连字符分隔的连续目标端口段: ")
        tgtPorts = tgtPorts_str.split(",")
        for tgtHost in subnet.hosts():
            tgtHost = str(tgtHost)
            portScan(tgtHost, tgtPorts, scanType.upper())
    elif scanObj.lower() == "iprange":
        startIP = input("输入起始 IP 地址: ")
        endIP = input("输入结束 IP 地址: ")
        try:
            start_ip = ipaddress.IPv4Address(startIP)
            end_ip = ipaddress.IPv4Address(endIP)
            if start_ip > end_ip:
                print("[!] 起始IP地址应该小于结束IP地址.")
                return
        except ValueError as e:
            print(e)
            return
        except Exception as e:
            print(e)
            return
        tgtPorts_str = input("输入用逗号分隔的目标端口号或用连字符分隔的连续目标端口段: ")
        tgtPorts = tgtPorts_str.split(",")
        for tgtHost in range(int(start_ip), int(end_ip) + 1):
            tgtHost = str(ipaddress.IPv4Address(tgtHost))
            if tgtHost != str(start_ip) and tgtHost != str(end_ip):
                portScan(tgtHost, tgtPorts, scanType.upper())
    else:
        print("指定的扫描对象无效. 程序退出.")
        return

    input("按任意键退出...")

if __name__ == '__main__':
    main()
