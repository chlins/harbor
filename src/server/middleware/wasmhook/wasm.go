package wasmhook

import (
	"context"
	"encoding/json"
	"os"

	"github.com/goharbor/harbor/src/common/security"
	"github.com/goharbor/harbor/src/controller/wasmhook"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func loadWasmHooks(ctx context.Context, hookInjectPoint string) error {
	hooks, err := wasmhook.Ctl.ListWasmHooks(ctx, hookInjectPoint)
	if err != nil {
		return err
	}

	logger := log.G(ctx).WithFields(log.Fields{"middleware": "wasmhook"})
	for _, hook := range hooks {
		req, err := buildRuntimeRequest(ctx)
		if err != nil {
			logger.Errorf("failed to build runtime request: %v", err)
			continue
		}

		resp, err := bootstrapWasmRuntime(ctx, hook.WasmProgram, hookInjectPoint, req)
		if err != nil {
			logger.Errorf("failed to bootstrap wasm runtime: %v", err)
			continue
		}

		// check runtime error
		if resp.RuntimeError != "" {
			logger.Errorf("wasm runtime error: %v", err)
			continue
		}

		if resp.Action == wasmhook.HookActionDeny && hook.HookMode == wasmhook.HookModeBlock {
			return errors.New(resp.Reason)
		}
	}

	return nil
}

func buildRuntimeRequest(ctx context.Context) (*wasmhook.RuntimeRequest, error) {
	none := lib.ArtifactInfo{}
	info := lib.GetArtifactInfo(ctx)
	if info == none {
		return nil, errors.New("artifactinfo middleware required").WithCode(errors.NotFoundCode)
	}

	req := &wasmhook.RuntimeRequest{
		Repository:  info.Repository,
		Reference:   info.Reference,
		ProjectName: info.ProjectName,
		Digest:      info.Digest,
		Tag:         info.Tag,
	}
	secCtx, ok := security.FromContext(ctx)
	if ok {
		req.Username = secCtx.GetUsername()
	}

	return req, nil
}

func bootstrapWasmRuntime(ctx context.Context, wasmProgram []byte, hookInjectPoint string, runtimeReq *wasmhook.RuntimeRequest) (*wasmhook.RuntimeResponse, error) {
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)

	// load WASI module
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		return nil, errors.Wrap(err, "failed to instantiate WASI")
	}

	// compile module
	module, err := runtime.CompileModule(ctx, wasmProgram)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compile module")
	}

	// initialize module
	instance, err := runtime.InstantiateModule(ctx, module, wazero.NewModuleConfig().WithStdout(os.Stdout).WithStderr(os.Stderr))
	if err != nil {
		return nil, errors.Wrap(err, "failed to instantiate module")
	}

	// load function
	hookWasi := instance.ExportedFunction(hookInjectPoint)
	if hookWasi == nil {
		return nil, errors.Wrapf(err, "function '%s' not found", hookInjectPoint)
	}

	// These are undocumented, but exported. See tinygo-org/tinygo#2788
	malloc := instance.ExportedFunction("malloc")
	free := instance.ExportedFunction("free")

	req, err := json.Marshal(runtimeReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode runtime request")
	}

	input := string(req)
	inputSize := uint64(len(input))

	results, err := malloc.Call(ctx, inputSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to malloc memory")
	}
	inputPtr := results[0]
	// This pointer is managed by TinyGo, but TinyGo is unaware of external usage.
	// So, we have to free it when finished
	defer free.Call(ctx, inputPtr)

	// The pointer is a linear memory offset, which is where we write the name.
	if !instance.Memory().Write(uint32(inputPtr), []byte(input)) {
		return nil, errors.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			inputPtr, inputSize, instance.Memory().Size())
	}

	ptrSize, err := hookWasi.Call(ctx, inputPtr, inputSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call wasi function")
	}

	outputPtr := uint32(ptrSize[0] >> 32)
	outputSize := uint32(ptrSize[0])

	// This pointer is managed by TinyGo, but TinyGo is unaware of external usage.
	// So, we have to free it when finished
	if outputPtr != 0 {
		defer func() {
			_, err := free.Call(ctx, uint64(outputPtr))
			if err != nil {
				log.Errorf("failed to call free: %v", err)
			}
		}()
	}

	// The pointer is a linear memory offset, which is where we write the name.
	if bytes, ok := instance.Memory().Read(outputPtr, outputSize); !ok {
		return nil, errors.Errorf("Memory.Read(%d, %d) out of range of memory size %d",
			outputPtr, outputSize, instance.Memory().Size())
	} else {
		var runtimeResp wasmhook.RuntimeResponse
		if err := json.Unmarshal(bytes, &runtimeResp); err != nil {
			return nil, errors.Wrap(err, "failed to decode runtime response")
		}

		return &runtimeResp, nil
	}
}
