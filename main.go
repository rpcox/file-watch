package main

// Importing required packages
import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const _tool = "file-notify"
const _version = "0.1"

var (
	_commit string
	_branch string
	debug   bool = false
)

type FileData struct {
	Name  string
	Mtime time.Time
}

type AuditPlan struct {
	DF       string // directory/file = 'd' or 'f'
	Presence int    // file is present, not deleted
	Mode     int    // e.g. 7555
	Atime    int    // file last access time
	Ctime    int    // file inode change time
	Mtime    int    // file last modification time
	Hash     string // md5, etc
	Path     string // fqp to file or directory
	Prune    string // a directory to skip
}

type AuditJob struct {
	FileList *[]FileData
	Audit    AuditPlan
}

// Build option to track git commit/build if desired
func Version(b bool) {
	if b {
		if _commit != "" {
			// go build -ldflags="-X main._commit=$(git rev-parse --short HEAD) -X main._branch=$(git branch | awk '{print $2}')"
			fmt.Fprintf(os.Stdout, "%s v%s (commit: %s, branch: %s)\n", _tool, _version, _commit, _branch)
		} else {
			// go build
			fmt.Fprintf(os.Stdout, "%s v%s\n", _tool, _version)
		}
		os.Exit(0)
	}
}

func TcpClient(tx string, retry, interval int) (net.Conn, error) {

	var conn net.Conn
	var err error

	for i := 1; i <= retry; i++ {
		conn, err = net.Dial("tcp", tx)
		if err == nil {
			break
		}

		if errors.Is(err, syscall.ECONNREFUSED) {
			log.Printf("TCP connection attempt %d: ECONNREFUSED: %v\n", i, err)
			if i == retry {
				err1 := errors.New("TCP connection attempts exhausted")
				return nil, err1
			}
		} else {
			return nil, err
		}

		time.Sleep(time.Duration(interval) * time.Second)
	}

	return conn, err
}

func _startLog(fileName string) *os.File {
	fLog, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Println(err)
		return nil
	}

	log.SetOutput(fLog)
	log.SetFlags(log.Lmicroseconds | log.LUTC | log.Ldate | log.Ltime)
	log.Printf("%s v%s starting\n", _tool, _version)
	log.Printf("debug: %v\n", debug)

	return fLog
}

func _loadAuditRules(confFile string) *[]AuditPlan {
	f, err := os.Open(confFile)
	if err != nil {
		s := fmt.Sprintf("fatal error: %v", err)
		fmt.Fprintf(os.Stderr, "%s\n", s)
		log.Fatal(s)
	}
	defer f.Close()

	apList := make([]AuditPlan, 0)

	scanner := bufio.NewScanner(f)

	comment, _ := regexp.Compile("^#")
	format, _ := regexp.Compile("^[^df]")

	planCount := 0
	for scanner.Scan() {
		field := strings.Split(scanner.Text(), "\t")

		if match := comment.MatchString(field[0]); match { // skip comments in config file
			continue
		}

		if match := format.MatchString(field[0]); match { // line must start w/ 'd' or 'f'
			continue
		}

		ap := AuditPlan{}

		ap.DF = field[0]

		if i, err := strconv.Atoi(field[1]); err == nil {
			ap.Presence = i
		} else {
			ap.Presence = 1
		}

		if i, err := strconv.Atoi(field[2]); err == nil {
			ap.Mode = i
		} else {
			ap.Mode = 0
		}

		if i, err := strconv.Atoi(field[3]); err == nil {
			ap.Atime = i
		} else {
			ap.Atime = 0
		}

		if i, err := strconv.Atoi(field[4]); err == nil {
			ap.Ctime = i
		} else {
			ap.Ctime = 0
		}

		if i, err := strconv.Atoi(field[5]); err == nil {
			ap.Mtime = i
		} else {
			ap.Mtime = 1
		}

		ap.Hash = field[6]
		ap.Path = field[7]
		ap.Prune = field[8]

		apList = append(apList, ap)
		planCount++
	}

	log.Printf("audit plans loaded: %d\n", planCount)
	return &apList
}

func _buildFileInvenory(ap AuditPlan) *[]FileData {
	fd := make([]FileData, 0)
	subDirToSkip := ap.Prune
	root := ap.Path

	err := filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		filedata := FileData{}

		if err != nil {
			fmt.Fprintf(os.Stderr, "error walking directory %q: %v\n", path, err)
			return err
		}

		if !info.IsDir() {
			filedata.Name = path
			filedata.Mtime = info.ModTime()
			fd = append(fd, filedata)
			log.Printf("add: mtime=%v file=%s", filedata.Mtime, filedata.Name)
		} else if info.IsDir() && info.Name() == subDirToSkip {
			log.Printf("skip: %v\n", path)
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		log.Printf("error walking directory %q: %v\n", root, err)
		return nil
	}

	return &fd
}

func _buildJobs(rules *[]AuditPlan) *[]AuditJob {

	jobs := make([]AuditJob, 0)

	line := 1
	for _, v := range *rules {
		a := AuditPlan{DF: v.DF, Presence: v.Presence, Mode: v.Mode, Atime: v.Atime, Ctime: v.Ctime, Mtime: v.Mtime, Hash: v.Hash, Path: v.Path, Prune: v.Prune}
		j := AuditJob{FileList: nil, Audit: a}
		j.FileList = _buildFileInvenory(a)
		if j.FileList == nil {
			s := fmt.Sprintf("skipping line %d of %s.rules. check rules and file system path", line, _tool)
			log.Println(s)
			fmt.Fprintln(os.Stderr, s)
			continue
		}
		jobs = append(jobs, j)
		line++
	}

	return &jobs
}

func Initialize(rules string) *[]AuditJob {
	auditRules := _loadAuditRules(rules)
	auditJobs := _buildJobs(auditRules)
	auditRules = nil
	return auditJobs
}

func AuditRun(ap AuditJob, jobNo int, tx string) int {

	job := fmt.Sprintf("job[%d]:", jobNo)
	alertBoard := make([]string, 0)
	for _, v := range *ap.FileList {
		if debug {
			log.Printf("%s audit %s", job, v.Name)
		}

		info, err := os.Stat(v.Name)
		if err != nil {
			s := fmt.Sprintf("%s file deletion: %v", job, err)
			log.Println(s)
			alertBoard = append(alertBoard, s)
			continue
		}

		if ap.Audit.Mtime == 1 {
			if info.ModTime() == v.Mtime {
				continue
			} else {
				s := fmt.Sprintf("%s mtime change: file=%s mtime1=%v mtime0=%v", job, v.Name, info.ModTime(), v.Mtime)
				log.Println(s)
				alertBoard = append(alertBoard, s)
			}
		}
	}

	n := len(alertBoard)
	log.Println(n, "alerts")

	if n > 0 {
		now := time.Now().Format(time.RFC3339)
		hostname, _ := os.Hostname()
		pid := os.Getpid()
		// <105> = audit.alert (facility.severity)
		hdr := fmt.Sprintf("<105>%v %v %s[%d] ", now, hostname, _tool, pid)
		client, err := TcpClient(tx, 2, 2)
		if err != nil {
			log.Println(err)
		}

		if client != nil {
			for _, v := range alertBoard {
				_, err = client.Write([]byte(hdr + v))
				if err != nil {
					log.Println(err)
				}
			}
			client.Close()
		}
	}

	return n
}

func RunJob(job AuditJob, jobNo, poll int, wg *sync.WaitGroup, tx string) {

	s := fmt.Sprintf("job[%d]:", jobNo)
	if debug {
		log.Printf("%s watching directory %s\n", s, job.Audit.Path)
		log.Printf("%s jitter %v", s, time.Duration(jobNo)*time.Minute)
	}

	time.Sleep(time.Duration(jobNo*30) * time.Second)
	log.Println(s, "entering audit loop")

	ticker := time.NewTicker(time.Duration(poll) * time.Minute)
	for range ticker.C {
		AuditRun(job, jobNo, tx)
	}
}

func main() {

	_dst := flag.String("dst", "127.0.0.1", "Destination hostname or IP address")
	_dport := flag.Int("dport", 6000, "Destination port")
	_debug := flag.Bool("debug", false, "Enable debug")
	_log := flag.String("log", "file-watch.log", "log file")
	_poll := flag.Int("poll", 1, "poll time")
	_rules := flag.String("rules", "file-watch.rules", "rules configuration file")
	_version := flag.Bool("version", false, "Display version and exit")
	flag.Parse()

	Version(*_version)
	debug = *_debug
	tx := *_dst + ":" + strconv.Itoa(*_dport)

	fhLog := _startLog(*_log)
	defer fhLog.Close()
	log.Printf("poll: %dm\n", *_poll)

	aj := Initialize(*_rules)

	var wg sync.WaitGroup

	for n, job := range *aj {
		go RunJob(job, n, *_poll, &wg, tx)
		wg.Add(1)
	}

	wg.Wait()
}
