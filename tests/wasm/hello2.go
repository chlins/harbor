package main

// #include <stdlib.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// tinygo build -o hello.wasm -scheduler=none -target=wasi main.go
// main is required for TinyGo to compile to Wasm.
func main() {}

// ptrToString returns a string from WebAssembly compatible numeric types
// representing its pointer and length.
func ptrToString(ptr uint32, size uint32) string {
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

// stringToLeakedPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The pointer is not automatically managed by TinyGo hence it must be freed by the host.
func stringToLeakedPtr(s string) (uint32, uint32) {
	size := C.ulong(len(s))
	ptr := unsafe.Pointer(C.malloc(size))
	copy(unsafe.Slice((*byte)(ptr), size), s)
	return uint32(uintptr(ptr)), uint32(size)
}

type RuntimeRequest struct {
	Username    string `json:"username"`
	Repository  string `json:"repository"`
	Reference   string `json:"reference"`
	ProjectName string `json:"project_name"`
	Digest      string `json:"digest"`
	Tag         string `json:"tag"`
}

type RuntimeResponse struct {
	Action       string `json:"action"` // pass or block
	Reason       string `json:"reason"`
	RuntimeError string `json:"runtime_error"`
}

func (rr *RuntimeResponse) EncodeToString() string {
	s, _ := json.Marshal(rr)
	return string(s)
}

func decodeRuntimeRequest(ptr, size uint32) (*RuntimeRequest, error) {
	str := ptrToString(ptr, size)
	var req RuntimeRequest
	if err := json.Unmarshal([]byte(str), &req); err != nil {
		return nil, err
	}

	return &req, nil
}

func encodeRuntimeResponse(rr *RuntimeResponse) uint64 {
	ptr, size := stringToLeakedPtr(rr.EncodeToString())
	return (uint64(ptr) << uint64(32)) | uint64(size)
}

//export before_pull
func _before_pull(ptr, size uint32) (ptrSize uint64) {
	var resp RuntimeResponse
	req, err := decodeRuntimeRequest(ptr, size)
	if err != nil {
		resp.RuntimeError = err.Error()
		return encodeRuntimeResponse(&resp)
	}

	res := before_pull(req)
	return encodeRuntimeResponse(res)
}

//export after_pull
func _after_pull(ptr, size uint32) (ptrSize uint64) {
	var resp RuntimeResponse
	req, err := decodeRuntimeRequest(ptr, size)
	if err != nil {
		resp.RuntimeError = err.Error()
		return encodeRuntimeResponse(&resp)
	}

	res := after_pull(req)
	return encodeRuntimeResponse(res)
}

func before_pull(req *RuntimeRequest) *RuntimeResponse {
	resp := &RuntimeResponse{}
	fmt.Println("################################### before pull: Hello WASM!")
	// do not allow alice pull image
	if req.Username == "alice" {
		resp.Action = "deny"
		resp.Reason = "alice not allowed to pull the image"
	}

	return resp
}

func after_pull(req *RuntimeRequest) *RuntimeResponse {
	resp := &RuntimeResponse{}
	fmt.Println("################################### after pull: Hello WASM!")
	return resp
}
