package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	//	"strings"
	//	"time"

	"github.com/gomodule/redigo/redis"
)

type dnsHeader struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

func (header *dnsHeader) SetFlag(QR uint16, OperationCode uint16, AuthoritativeAnswer uint16, Truncation uint16,
	RecursionDesired uint16, RecursionAvailable uint16, ResponseCode uint16) {
	header.Bits = QR<<15 + OperationCode<<11 + AuthoritativeAnswer<<10 + Truncation<<9 + RecursionDesired<<8 + RecursionAvailable<<7 + ResponseCode
}

type dnsQuery struct {
	QuestionType  uint16
	QuestionClass uint16
}

type dnsResponse struct {
	QuestionType  uint16
	QuestionClass uint16
	TTL           uint32
	DataLen       uint16
	IP            uint32
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Error: %s", err.Error())
		os.Exit(1)
	}
}

func ParseDomainName(buffer *bytes.Reader) string {
	var domain string

	log.Printf("buffer.size():%d\n", buffer.Size())

	for {
		byteSegLen, _ := buffer.ReadByte()
		log.Printf("byteSegLen:%d\n", byteSegLen)
		if byteSegLen == 0 {
			break
		}
		seg := make([]byte, byteSegLen)
		binary.Read(buffer, binary.BigEndian, &seg)
		log.Printf("seg_len:%d,%s,buffer.size():%d\n", len(seg), string(seg), buffer.Size())
		if len(domain) > 0 {
			domain = domain + "."
		}
		domain = domain + string(seg)
	}

	return domain
}

func recvUDPMsg(conn *net.UDPConn) {
	var buf [1024]byte

	n, raddr, err := conn.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}

	requestHeader := dnsHeader{
		Id:      0x0010,
		Qdcount: 1,
		Ancount: 0,
		Nscount: 0,
		Arcount: 0,
	}
	requestHeader.SetFlag(0, 0, 0, 0, 1, 0, 0)

	requestQuery := dnsQuery{
		QuestionType:  1,
		QuestionClass: 1,
	}

	buffer := bytes.NewReader(buf[0:])
	binary.Read(buffer, binary.BigEndian, &requestHeader)
	domain := ParseDomainName(buffer)
	binary.Read(buffer, binary.BigEndian, &requestQuery)

	fmt.Printf("query req n:%d, domain is %s\n", n, domain)

	strIp := "0.0.0.0"

	if len(domain) > len("home.ddns.flowheart.cn") {
		start_pos := len(domain) - len("home.ddns.flowheart.cn")
		domain = domain[start_pos:]
	}

	fmt.Printf("proccess, domain is %s\n", domain)

	strIp = get_domain_ip(domain)
	if strIp == "" {
		if domain == "home.ddns.flowheart.cn" {
			ns, err := net.LookupHost("heyg.xicp.net")
			if err != nil {
				log.Println(err)
				return
			} else {
				strIp = ns[0]
			}
		}
	}

	sendRsp(conn, raddr, requestHeader.Id, domain, strIp)
}

func get_domain_ip(domain string) string {
	c, err := redis.Dial("tcp", "127.0.0.1:6379")
	if err != nil {
		log.Println(err)
		return ""
	}
	defer c.Close()

	v, err := redis.String(c.Do("GET", domain))
	if err != nil {
		log.Println(err)
		return ""
	}
	log.Println(v)

	return v
}

func sendRsp(conn *net.UDPConn, raddr *net.UDPAddr, TransId uint16, domain string, strIp string) {

	requestHeader := dnsHeader{
		Id:      TransId,
		Qdcount: 1,
		Ancount: 1,
		Nscount: 0,
		Arcount: 0,
	}
	requestHeader.SetFlag(0, 0, 0, 0, 1, 0, 0)
	requestHeader.Bits = 0x8180

	requestQuery := dnsQuery{
		QuestionType:  1,
		QuestionClass: 1,
	}

	var answer dnsResponse
	answer.QuestionType = 1
	answer.QuestionClass = 0x0001
	answer.TTL = 60
	answer.DataLen = 4
	answer.IP = uint32(InetAtoN(strIp))

	var buffer bytes.Buffer

	binary.Write(&buffer, binary.BigEndian, requestHeader)
	binary.Write(&buffer, binary.BigEndian, WriteDomainName(domain))
	binary.Write(&buffer, binary.BigEndian, requestQuery)
	binary.Write(&buffer, binary.BigEndian, WriteDomainName(domain))
	binary.Write(&buffer, binary.BigEndian, answer)

	//WriteToUDP
	//func (c *UDPConn) WriteToUDP(b []byte, addr *UDPAddr) (int, error)
	_, err := conn.WriteToUDP(buffer.Bytes(), raddr)
	checkError(err)
}

/*
func Send(dnsServer, domain string) ([]byte, int, time.Duration) {
	requestHeader := dnsHeader{
		Id:      0x0010,
		Qdcount: 1,
		Ancount: 1,
		Nscount: 0,
		Arcount: 0,
	}
	requestHeader.SetFlag(0, 0, 0, 0, 1, 0, 0)

	requestQuery := dnsQuery{
		QuestionType:  1,
		QuestionClass: 1,
	}

	var (
		conn   net.Conn
		err    error
		buffer bytes.Buffer
	)

	if conn, err = net.Dial("udp", dnsServer); err != nil {
		fmt.Println(err.Error())
		return make([]byte, 0), 0, 0
	}
	defer conn.Close()

	binary.Write(&buffer, binary.BigEndian, requestHeader)
	binary.Write(&buffer, binary.BigEndian, ParseDomainName(domain))
	binary.Write(&buffer, binary.BigEndian, requestQuery)

	buf := make([]byte, 1024)
	t1 := time.Now()
	if _, err := conn.Write(buffer.Bytes()); err != nil {
		fmt.Println(err.Error())
		return make([]byte, 0), 0, 0
	}
	length, err := conn.Read(buf)
	t := time.Now().Sub(t1)
	return buf, length, t
}
*/
func InetAtoN(ip string) int64 {
	ret := big.NewInt(0)
	ret.SetBytes(net.ParseIP(ip).To4())
	return ret.Int64()
}

func WriteDomainName(domain string) []byte {
	var (
		buffer   bytes.Buffer
		segments []string = strings.Split(domain, ".")
	)
	for _, seg := range segments {
		binary.Write(&buffer, binary.BigEndian, byte(len(seg)))
		binary.Write(&buffer, binary.BigEndian, []byte(seg))
	}
	binary.Write(&buffer, binary.BigEndian, byte(0x00))

	return buffer.Bytes()
}

func main() {
	udp_addr, err := net.ResolveUDPAddr("udp", ":53")
	checkError(err)

	conn, err := net.ListenUDP("udp", udp_addr)
	defer conn.Close()
	checkError(err)

	//go recvUDPMsg(conn)
	for {
		recvUDPMsg(conn)
	}
}
