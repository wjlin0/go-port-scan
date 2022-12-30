package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type GetInfo struct {
	Url  string `json:"url"`
	Port string `json:"port"`
	Code bool   `json:"code"`
}

var (
	port       = flag.String("p", "1,7,9,13,19,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,402,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,873,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2082,2083,2100,2103,2121,2199,2207,2222,2323,2362,2375,2380-2381,2525,2533,2598,2601,2604,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3311,3312,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4433,4444-4445,4659,4679,4848,5000,5038,5040,5051,5060-5061,5093,5168,5247,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5601,5631-5632,5666,5800,5814,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6082,6101,6106,6112,6262,6379,6405,6502-6504,6542,6660-6661,6667,6905,6988,7001,7021,7071,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777-7778,7787,7800-7801,7879,7902,8000-8001,8008,8014,8020,8023,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9002,9060,9080-9081,9084,9090,9099-9100,9111,9152,9200,9390-9391,9443,9495,9809-9815,9855,9999-10001,10008,10050-10051,10080,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12221,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32764,32913,34205,34443,37718,38080,38292,40007,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,52302,55553,57772,62078,62514,65535", "扫描端口")
	socksProxy = flag.String("s", "", "socks5代理")
	url_       = flag.String("u", "", "扫描目标")
	thread     = flag.Int("t", 20, "多少个端口同时扫描")
	path       = flag.String("f", "./output", "输出路径")
	outMethod  = flag.String("o", "", "输出模式csv,json")
	//wg sync.WaitGroup
)

type Socks5Client struct {
	proxyUrl *url.URL
}

type DefaultClient struct {
}

func (d *DefaultClient) Dial(network string, address string) (conn net.Conn, err error) {
	return net.DialTimeout(network, address, 10*time.Second)
}
func (s5 *Socks5Client) Dial(network string, address string) (net.Conn, error) {
	d, err := proxy.SOCKS5(network, strings.Replace(s5.proxyUrl.String(), "socks5://", "", -1), nil, &net.Dialer{
		Timeout: time.Second,
	})

	if err != nil {
		return nil, err
	}
	return d.Dial(network, address)
}

func NewDial(proxyUrl string) (proxy.Dialer, error) {
	parse, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, err
	}
	switch parse.Scheme {
	case "socks5":
		return &Socks5Client{parse}, nil
	default:
		return &DefaultClient{}, nil
	}
}

func Banner() {

	fmt.Println(`
           __.__  .__       _______   
__  _  __ |__|  | |__| ____ \   _  \  
\ \/ \/ / |  |  | |  |/    \/  /_\  \ 
 \     /  |  |  |_|  |   |  \  \_/   \
  \/\_/\__|  |____/__|___|  /\_____  /
      \______|            \/       \/ 
        go-port-scan `)
}
func Exists(p string) bool {
	_, err := os.Stat(p) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func checkArg() (urls, ports []string) {
	temp := strings.Split(*port, ",")
	for _, t := range temp {
		if strings.IndexByte(t, '-') != -1 {
			p := strings.Split(t, "-")
			min, _ := strconv.Atoi(p[0])
			max, _ := strconv.Atoi(p[1])
			for i := min; i <= max; i++ {
				ports = append(ports, strconv.Itoa(i))
			}
		} else {
			if t == "" {
				continue
			}
			ports = append(ports, t)
		}
	}
	urls = strings.Split(*url_, ",")
	if !strings.HasSuffix(*path, "/") {
		*path = *path + "/"
	}
	if !Exists(*path) {
		err := os.MkdirAll(*path, os.ModePerm)
		if err != nil {
			fmt.Println("创建文件失败")
			os.Exit(0)
		}
	}
	if urls[0] == "" {
		flag.Usage()
		os.Exit(0)
	}
	if ports[0] == "" {
		flag.Usage()
		os.Exit(0)
	}
	return
}

func main() {
	Banner()

	flag.Parse()
	urls, ports := checkArg()
	ch := make(chan *GetInfo, *thread)
	infoMap := make(map[string]map[string]bool)
	d, err := NewDial(*socksProxy)
	if err != nil {
		panic(err)
	}
	for _, u := range urls {
		t := make(map[string]bool)
		for _, p := range ports {
			//wg.Add(1)
			go tcpGo(u, p, d, ch)
		}
		//
		for _, _ = range ports {
			info := <-ch
			t[info.Port] = info.Code
		}
		infoMap[u] = t
	}
	Output(&infoMap)
	//wg.Wait()
}
func tcpGo(url string, port string, d proxy.Dialer, ch chan *GetInfo) {

	info := &GetInfo{
		Url:  url,
		Port: port,
		Code: false,
	}

	conn, err := d.Dial("tcp", url+":"+port)
	if err != nil {
		ch <- info
	} else {
		_ = conn.Close()
		info.Code = true
		ch <- info
	}
	//wg.Done()
}
func Output(infos *map[string]map[string]bool) {

	for k, v := range *infos {

		t := map[string]map[string]bool{
			k: v,
		}
		switch *outMethod {
		case "csv":
			filename := *path + k + ".csv"
			csvWriter(filename, t)
		case "json":
			filename := *path + k + ".json"
			jsonWrite(filename, t)
		default:

		}
		fmt.Println(k)
		for vk, vv := range v {
			if vv {
				fmt.Printf("\t%v %v\n", vk, vv)
			}

		}
	}

}
func csvWriter(filename string, data map[string]map[string]bool) {

	File, err := os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Println("文件打开失败！")
	}
	defer File.Close()
	var b []byte
	read, err := File.Read(b[:])
	if err != nil {
		return
	}
	//创建写入接口

	WriterCsv := csv.NewWriter(File)
	if read == 0 {
		err := WriterCsv.Write([]string{"port", "code"})
		if err != nil {
			fmt.Println("写入失败")
			return
		}
		WriterCsv.Flush()
	}
	for _, v := range data {
		for vk, vv := range v {
			str := []string{vk, strconv.FormatBool(vv)}
			err := WriterCsv.Write(str)
			if err != nil {
				continue
			}
			WriterCsv.Flush()
		}
	}
}
func jsonWrite(filename string, data map[string]map[string]bool) {
	//fmt.Println(filename)
	file, _ := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	defer file.Close()
	marshal, err := json.Marshal(data)
	if err != nil {
		return
	}
	_, err = file.WriteString(string(marshal[:]))
	if err != nil {
		return
	}

}
