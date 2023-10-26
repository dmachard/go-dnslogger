package transformers

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

type expiredKey struct {
	key     string
	expTime time.Time
}

type MapTraffic struct {
	sync.RWMutex
	ttl          time.Duration
	kv           *sync.Map
	channels     []chan dnsutils.DnsMessage
	expiredKeys  *list.List
	droppedCount int
	logInfo      func(msg string, v ...interface{})
	logError     func(msg string, v ...interface{})
}

func NewMapTraffic(ttl time.Duration, channels []chan dnsutils.DnsMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) MapTraffic {
	return MapTraffic{
		ttl:         ttl,
		kv:          &sync.Map{},
		channels:    channels,
		expiredKeys: list.New(),
		logInfo:     logInfo,
		logError:    logError,
	}
}

func (mp *MapTraffic) SetTtl(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapTraffic) Set(key string, dm *dnsutils.DnsMessage) {
	mp.Lock()
	defer mp.Unlock()

	if v, ok := mp.kv.Load(key); ok {
		v.(*dnsutils.DnsMessage).Reducer.Occurences++
		v.(*dnsutils.DnsMessage).Reducer.CumulativeLength += dm.DNS.Length
		return
	}

	dm.Reducer.Occurences = 1
	dm.Reducer.CumulativeLength = dm.DNS.Length
	mp.kv.Store(key, dm)

	expTime := time.Now().Add(mp.ttl)
	mp.expiredKeys.PushBack(expiredKey{key, expTime})

}

func (mp *MapTraffic) Run() {
	flushTimer := time.NewTimer(mp.ttl)
	for range flushTimer.C {
		if mp.droppedCount > 0 {
			mp.logError("reducer: event(s) %d dropped, output channel full", mp.droppedCount)
			mp.droppedCount = 0
		}
		mp.ProcessExpiredKeys()
		flushTimer.Reset(mp.ttl)
	}
}

func (mp *MapTraffic) ProcessExpiredKeys() {
	mp.Lock()
	defer mp.Unlock()

	now := time.Now()

	for e := mp.expiredKeys.Front(); e != nil; {
		expired := e.Value.(expiredKey)
		if now.Before(expired.expTime) {
			break
		}
		key := expired.key
		if v, ok := mp.kv.Load(key); ok {
			for i := range mp.channels {
				mp.channels[i] <- *v.(*dnsutils.DnsMessage)
			}
			mp.kv.Delete(key)
		}

		next := e.Next()
		mp.expiredKeys.Remove(e)
		e = next
	}
}

type ReducerProcessor struct {
	config           *dnsutils.ConfigTransformers
	logger           *logger.Logger
	name             string
	instance         int
	outChannels      []chan dnsutils.DnsMessage
	activeProcessors []func(dm *dnsutils.DnsMessage) int
	mapTraffic       MapTraffic
	logInfo          func(msg string, v ...interface{})
	logError         func(msg string, v ...interface{})
	strBuilder       strings.Builder
}

func NewReducerSubprocessor(
	config *dnsutils.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DnsMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{}),
) *ReducerProcessor {
	s := ReducerProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
		logInfo:     logInfo,
		logError:    logError,
	}

	s.mapTraffic = NewMapTraffic(time.Duration(config.Reducer.WatchInterval)*time.Second, outChannels, logInfo, logError)
	return &s
}

func (p *ReducerProcessor) ReloadConfig(config *dnsutils.ConfigTransformers) {
	p.config = config
	p.mapTraffic.SetTtl(time.Duration(config.Reducer.WatchInterval) * time.Second)

	p.LoadActiveReducers()
}

func (p *ReducerProcessor) LoadActiveReducers() {
	// clean the slice
	p.activeProcessors = p.activeProcessors[:0]

	if p.config.Reducer.RepetitiveTrafficDetector {
		p.activeProcessors = append(p.activeProcessors, p.RepetitiveTrafficDetector)
		go p.mapTraffic.Run()
	}
}

func (p *ReducerProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	if dm.Reducer == nil {
		dm.Reducer = &dnsutils.TransformReducer{
			Occurences:       0,
			CumulativeLength: 0,
		}
	}
}

func (p *ReducerProcessor) RepetitiveTrafficDetector(dm *dnsutils.DnsMessage) int {
	p.strBuilder.Reset()
	p.strBuilder.WriteString(dm.DnsTap.Identity)
	p.strBuilder.WriteString(dm.DnsTap.Operation)
	p.strBuilder.WriteString(dm.NetworkInfo.QueryIp)
	if p.config.Reducer.QnamePlusOne {
		qname := strings.ToLower(dm.DNS.Qname)
		qname = strings.TrimSuffix(qname, ".")
		if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
			dm.DNS.Qname = etld
		}
	}
	p.strBuilder.WriteString(dm.DNS.Qname)
	p.strBuilder.WriteString(dm.DNS.Qtype)
	dmTag := p.strBuilder.String()

	p.mapTraffic.Set(dmTag, dm)

	return RETURN_DROP
}

func (s *ReducerProcessor) ProcessDnsMessage(dm *dnsutils.DnsMessage) int {
	dmCopy := *dm

	if len(s.activeProcessors) == 0 {
		return RETURN_SUCCESS
	}

	var r_code int
	for _, fn := range s.activeProcessors {
		r_code = fn(&dmCopy)
		if r_code != RETURN_SUCCESS {
			return r_code
		}
	}

	return RETURN_SUCCESS
}
