package proxy

import (
	"bytes"
	"fmt"
	"sync"
)

type Forwarder struct {
	Offset int
	Data   []byte
	mutex  sync.RWMutex
}

func NewForwarder() *Forwarder {
	return &Forwarder{
		Offset: 0,
		Data:   make([]byte, 0),
		mutex:  sync.RWMutex{},
	}
}

func (f *Forwarder) Write(p []byte) int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.Data = append(f.Data, p...)
	return len(p)
}

func (f *Forwarder) Read() (int, []byte, []byte, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.Offset >= len(f.Data) {
		return 0, nil, nil, fmt.Errorf("no more data")
	}

	data := f.Data[f.Offset:]
	doneFlagIndex := bytes.Index(f.Data, []byte{0, 0, 0, 0})
	toolCallsFlagIndex := bytes.Index(f.Data, []byte{0, 0, 0, 1})
	if doneFlagIndex == -1 && toolCallsFlagIndex == -1 {
		f.Offset = len(f.Data)
		return len(data), data, nil, nil
	} else {
		if toolCallsFlagIndex == -1 {
			data = f.Data[f.Offset:doneFlagIndex]
			f.Data = f.Data[doneFlagIndex+4:]
			f.Offset = 0
			return len(data), data, nil, fmt.Errorf("done")
		} else {
			data = f.Data[f.Offset:toolCallsFlagIndex]
			toolCalls := f.Data[toolCallsFlagIndex+4 : doneFlagIndex]
			f.Data = f.Data[doneFlagIndex+4:]
			f.Offset = 0
			return len(data), data, toolCalls, fmt.Errorf("done")
		}
	}
}
