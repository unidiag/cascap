package main

//  apt-get install libpcap-dev

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	// Проверка наличия значений IP-адресов
	if len(os.Args) < 2 || len(os.Args) > 3 {
		log.Fatalf("Usage: ./%s ip [port]", os.Args[0])
	}

	ip1 := os.Args[1]

	// Получение списка всех доступных интерфейсов
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Ошибка при получении списка интерфейсов: %v", err)
	}

	if len(interfaces) == 0 {
		log.Fatal("Нет доступных интерфейсов для захвата.")
	}

	// Выбор первого интерфейса в списке
	defaultInterface := interfaces[0].Name
	fmt.Printf("Используется интерфейс: %s ", defaultInterface)

	// Получение IP-адреса первого интерфейса
	var interfaceIP string
	for _, address := range interfaces[0].Addresses {
		if address.IP.To4() != nil { // Проверка, что это IPv4 адрес
			interfaceIP = address.IP.String()
			break
		}
	}

	if interfaceIP == "" {
		fmt.Printf("( unknown )\n")
		os.Exit(1)
	} else {
		fmt.Printf("( %s )\n", interfaceIP)
	}

	// Открытие интерфейса для захвата пакетов
	handle, err := pcap.OpenLive(defaultInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Ошибка при открытии интерфейса: %v", err)
	}
	defer handle.Close()

	// Установите BPF фильтр для захвата пакетов между двумя хостами
	filter := fmt.Sprintf("tcp and host %s and host %s", interfaceIP, ip1)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Ошибка при установке фильтра: %v", err)
	}

	// Создайте пакетный источник
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Читаем пакеты в бесконечном цикле
	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
		// Попробуйте извлечь слой TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Проверка флага PSH
			if tcp.PSH {
				// Извлечение слоя IP
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					//ip, _ := ipLayer.(*layers.IPv4)

					// Определение направления пакета и вывод данных
					//forw := ">"
					// if ip.SrcIP.String() == interfaceIP && ip.DstIP.String() == ip1 {
					// 	forw = "<"
					// }

					srcport := tcp.SrcPort.String()
					dstport := tcp.DstPort.String()

					if len(os.Args) == 2 {
						fmt.Printf("%s %d:%d %02X\n", timestamp, tcp.SrcPort, tcp.DstPort, tcp.LayerPayload())
					} else if srcport == os.Args[2] || dstport == os.Args[2] {
						fmt.Printf("%s %d:%d %02X\n", timestamp, tcp.SrcPort, tcp.DstPort, tcp.LayerPayload())
					}
				}
			}
		}
	}
}
