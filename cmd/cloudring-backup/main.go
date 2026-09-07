// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/opencloudtech/CloudRING/internal/privateartifact"
	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/backup/drill"
	"github.com/opencloudtech/CloudRING/pkg/backup/restoreproof"
	"github.com/opencloudtech/CloudRING/pkg/backup/velero118"
	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
	"github.com/opencloudtech/CloudRING/pkg/secureexec"
)

const maxPrivateArtifactBytes = 8 << 20

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "cloudring-backup: operation failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("command is required")
	}
	switch arguments[0] {
	case "baseline":
		return runBaseline(ctx, arguments[1:], stdout)
	case "observe-data-upload-result":
		return runObserveDataUploadResult(ctx, arguments[1:], stdout)
	case "collect":
		return runCollect(ctx, arguments[1:], stdout)
	case "verify":
		return runVerify(arguments[1:], stdout)
	case "drill":
		return runDrill(ctx, arguments[1:], stdout)
	default:
		return errors.New("unknown command")
	}
}

func runDrill(ctx context.Context, arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("backup drill command is required")
	}
	switch arguments[0] {
	case "preflight":
		return runDrillPreflight(ctx, arguments[1:], stdout)
	case "apply":
		return runDrillApply(ctx, arguments[1:], stdout, false)
	case "recover":
		return runDrillApply(ctx, arguments[1:], stdout, true)
	case "rollback":
		return runDrillRollback(ctx, arguments[1:], stdout)
	default:
		return errors.New("unknown backup drill command")
	}
}

func runDrillPreflight(ctx context.Context, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("drill preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "strict versioned drill plan JSON")
	adapterPath := flags.String("adapter", "", "absolute reviewed adapter executable")
	var adapterEnvironmentNames []string
	flags.Func("adapter-env", "explicit environment variable name to pass to the pinned adapter; repeat for each name", func(name string) error {
		adapterEnvironmentNames = append(adapterEnvironmentNames, name)
		return kubeconfigpipe.ValidateEnvironmentNames(adapterEnvironmentNames)
	})
	approvalPath := flags.String("approval", "", "new owner-only approval report")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig; consumed once and replayed in memory")
	timeout := flags.Duration("timeout", 2*time.Minute, "adapter execution timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *planPath == "" || *adapterPath == "" || *approvalPath == "" || *kubeconfigFD < 3 || *timeout <= 0 {
		return errors.New("invalid backup drill preflight arguments")
	}
	if err := validateNewArtifactDestinations(*approvalPath); err != nil {
		return errors.New("backup drill approval destination is unavailable")
	}
	replay, err := kubeconfigpipe.NewFromFD(*kubeconfigFD)
	if err != nil {
		return errors.New("read backup drill pipe-backed kubeconfig")
	}
	defer replay.Close()
	adapter, err := drill.PinAdapterWithEnvironmentNames(*adapterPath, *timeout, replay, adapterEnvironmentNames)
	if err != nil {
		return err
	}
	defer adapter.Close()
	var plan drill.Plan
	if err := readStrictJSON(*planPath, &plan); err != nil {
		return errors.New("read backup drill plan")
	}
	if err := validateDrillToolIdentity(plan); err != nil {
		return err
	}
	report, err := drill.Preflight(ctx, plan, adapter, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := privateartifact.WriteNewJSON(*approvalPath, report); err != nil {
		return errors.New("write backup drill approval report")
	}
	_, _ = fmt.Fprintf(stdout, "status=preflight-approved tuple=%s\n", report.ApprovalTuple)
	return nil
}

func runDrillApply(ctx context.Context, arguments []string, stdout io.Writer, recoverRun bool) error {
	name := "drill apply"
	if recoverRun {
		name = "drill recover"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "strict versioned drill plan JSON")
	approvalPath := flags.String("approval", "", "owner-only approval report")
	adapterPath := flags.String("adapter", "", "absolute reviewed adapter executable")
	var adapterEnvironmentNames []string
	flags.Func("adapter-env", "explicit environment variable name to pass to the pinned adapter; repeat for each name", func(name string) error {
		adapterEnvironmentNames = append(adapterEnvironmentNames, name)
		return kubeconfigpipe.ValidateEnvironmentNames(adapterEnvironmentNames)
	})
	journalPath := flags.String("journal", "", "owner-only append-only drill journal")
	receiptPath := flags.String("receipt", "", "new owner-only execution receipt")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig; consumed once and replayed in memory")
	confirmation := flags.String("confirm", "", "exact preflight-bound approval tuple")
	timeout := flags.Duration("timeout", 10*time.Minute, "per-adapter-step timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *planPath == "" || *approvalPath == "" || *adapterPath == "" || *journalPath == "" || *receiptPath == "" || *kubeconfigFD < 3 || *timeout <= 0 || *confirmation == "" {
		return errors.New("invalid backup drill execution arguments")
	}
	if err := validateNewArtifactDestinations(*receiptPath); err != nil {
		return errors.New("backup drill receipt destination is unavailable")
	}
	if !recoverRun {
		if err := validateNewArtifactDestinations(*journalPath); err != nil || samePath(*journalPath, *receiptPath) {
			return errors.New("backup drill journal destination is unavailable")
		}
	}
	replay, err := kubeconfigpipe.NewFromFD(*kubeconfigFD)
	if err != nil {
		return errors.New("read backup drill pipe-backed kubeconfig")
	}
	defer replay.Close()
	adapter, err := drill.PinAdapterWithEnvironmentNames(*adapterPath, *timeout, replay, adapterEnvironmentNames)
	if err != nil {
		return err
	}
	defer adapter.Close()
	var plan drill.Plan
	if err := readStrictJSON(*planPath, &plan); err != nil {
		return errors.New("read backup drill plan")
	}
	if err := validateDrillToolIdentity(plan); err != nil {
		return err
	}
	var approval drill.ApprovalReport
	if err := privateartifact.ReadJSON(*approvalPath, &approval); err != nil {
		return errors.New("read backup drill approval")
	}
	var receipt drill.ExecutionReceipt
	if recoverRun {
		receipt, err = drill.Recover(ctx, plan, approval, *confirmation, *journalPath, adapter, drill.SystemClock)
	} else {
		receipt, err = drill.Apply(ctx, plan, approval, *confirmation, *journalPath, adapter, drill.SystemClock)
	}
	if err != nil {
		return err
	}
	if err := privateartifact.WriteNewJSON(*receiptPath, receipt); err != nil {
		return errors.New("write backup drill execution receipt")
	}
	_, _ = fmt.Fprintln(stdout, "status=drill-completed")
	return nil
}

func runDrillRollback(ctx context.Context, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("drill rollback", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "strict versioned drill plan JSON")
	approvalPath := flags.String("approval", "", "owner-only approval report")
	adapterPath := flags.String("adapter", "", "absolute reviewed adapter executable")
	var adapterEnvironmentNames []string
	flags.Func("adapter-env", "explicit environment variable name to pass to the pinned adapter; repeat for each name", func(name string) error {
		adapterEnvironmentNames = append(adapterEnvironmentNames, name)
		return kubeconfigpipe.ValidateEnvironmentNames(adapterEnvironmentNames)
	})
	journalPath := flags.String("journal", "", "owner-only append-only drill journal")
	confirmation := flags.String("confirm", "", "exact preflight-bound approval tuple")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig; consumed once and replayed in memory")
	timeout := flags.Duration("timeout", 10*time.Minute, "per-adapter-step timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *planPath == "" || *approvalPath == "" || *adapterPath == "" || *journalPath == "" || *confirmation == "" || *kubeconfigFD < 3 || *timeout <= 0 {
		return errors.New("invalid backup drill rollback arguments")
	}
	replay, err := kubeconfigpipe.NewFromFD(*kubeconfigFD)
	if err != nil {
		return errors.New("read backup drill pipe-backed kubeconfig")
	}
	defer replay.Close()
	adapter, err := drill.PinAdapterWithEnvironmentNames(*adapterPath, *timeout, replay, adapterEnvironmentNames)
	if err != nil {
		return err
	}
	defer adapter.Close()
	var plan drill.Plan
	if err := readStrictJSON(*planPath, &plan); err != nil {
		return errors.New("read backup drill plan")
	}
	if err := validateDrillToolIdentity(plan); err != nil {
		return err
	}
	var approval drill.ApprovalReport
	if err := privateartifact.ReadJSON(*approvalPath, &approval); err != nil {
		return errors.New("read backup drill approval")
	}
	if err := drill.Rollback(ctx, plan, approval, *confirmation, *journalPath, adapter, drill.SystemClock); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "status=drill-rolled-back")
	return nil
}

func validateDrillToolIdentity(plan drill.Plan) error {
	path, err := os.Executable()
	if err != nil {
		return errors.New("resolve backup drill tool identity")
	}
	pinned, err := secureexec.PinAbsolute(path, time.Minute)
	if err != nil {
		return errors.New("pin backup drill tool identity")
	}
	defer pinned.Close()
	if pinned.IdentitySHA256() != plan.Tool.ExecutableSHA256 {
		return errors.New("backup drill tool executable digest differs from plan")
	}
	return nil
}

func runObserveDataUploadResult(ctx context.Context, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("observe-data-upload-result", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "DataUploadResult observation request JSON")
	outputPath := flags.String("output", "", "new private DataUploadResult observation file")
	readyPath := flags.String("ready", "", "new private ready-for-Restore marker")
	kubectl := flags.String("kubectl", "kubectl", "kubectl executable")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig; consumed once and replayed in memory")
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum observation duration")
	pollInterval := flags.Duration("poll-interval", 200*time.Millisecond, "observation polling interval")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *requestPath == "" || *outputPath == "" || *readyPath == "" || samePath(*readyPath, *outputPath) || *timeout <= 0 || *pollInterval <= 0 || *pollInterval > *timeout {
		return errors.New("invalid DataUploadResult observation arguments")
	}
	if err := validateNewArtifactDestinations(*readyPath, *outputPath); err != nil {
		return errors.New("DataUploadResult observation destination is unavailable")
	}
	var request velero118.DataUploadResultObservationRequest
	if err := readStrictJSON(*requestPath, &request); err != nil {
		return errors.New("read DataUploadResult observation request")
	}
	reader, err := newCollectorKubectlReader(*kubectl, *kubeconfigFD)
	if err != nil {
		return err
	}
	defer reader.Close()
	observation, err := velero118.ObserveDataUploadResult(ctx, reader, fileObservationReadyBarrier{path: *readyPath}, request, *timeout, *pollInterval, velero118.SystemClock())
	if err != nil {
		return err
	}
	defer zeroBytes(observation.Object)
	if err := writePrivateJSON(*outputPath, observation); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "status=data_upload_result_observation_written")
	return nil
}

func runBaseline(ctx context.Context, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "baseline request JSON")
	outputPath := flags.String("output", "", "new private baseline file")
	kubectl := flags.String("kubectl", "kubectl", "kubectl executable")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig; consumed once and replayed in memory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *requestPath == "" || *outputPath == "" {
		return errors.New("invalid baseline arguments")
	}
	if err := validateNewArtifactDestinations(*outputPath); err != nil {
		return errors.New("baseline output destination is unavailable")
	}
	var request velero118.BaselineRequest
	if err := readStrictJSON(*requestPath, &request); err != nil {
		return errors.New("read baseline request")
	}
	reader, err := newCollectorKubectlReader(*kubectl, *kubeconfigFD)
	if err != nil {
		return err
	}
	defer reader.Close()
	baseline, err := velero118.BuildSourceBaseline(ctx, reader, request, velero118.SystemClock())
	if err != nil {
		return err
	}
	if err := writePrivateJSON(*outputPath, baseline); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "status=baseline_written")
	return nil
}

func runCollect(ctx context.Context, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("collect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "collection request JSON")
	baselinePath := flags.String("baseline", "", "private source baseline JSON")
	archivePath := flags.String("archive", "", "Velero BackupContents tar.gz")
	resultObservationPath := flags.String("data-upload-result-observation", "", "private pre-terminal DataUploadResult observation JSON")
	probeAdapterPath := flags.String("data-probe-adapter", "", "absolute probe adapter executable")
	providerAdapterPath := flags.String("provider-adapter", "", "absolute provider observer executable")
	cleanupReadyPath := flags.String("cleanup-ready", "", "new atomic ready-for-cleanup marker")
	outputPath := flags.String("output", "", "new private receipt file")
	kubectl := flags.String("kubectl", "kubectl", "kubectl executable")
	kubeconfigFD := flags.Int("kubeconfig-fd", -1, "pipe descriptor containing kubeconfig; consumed once and replayed in memory")
	cleanupTimeout := flags.Duration("cleanup-timeout", 30*time.Minute, "maximum wait for downstream cleanup")
	pollInterval := flags.Duration("poll-interval", 2*time.Second, "cleanup observation interval")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *requestPath == "" || *baselinePath == "" || *archivePath == "" || *resultObservationPath == "" ||
		*probeAdapterPath == "" || *providerAdapterPath == "" || *cleanupReadyPath == "" || *outputPath == "" || *cleanupTimeout <= 0 || *pollInterval <= 0 || samePath(*cleanupReadyPath, *outputPath) {
		return errors.New("invalid collect arguments")
	}
	if err := validateNewArtifactDestinations(*cleanupReadyPath, *outputPath); err != nil {
		return errors.New("collect artifact destination is unavailable")
	}
	var request velero118.CollectionRequest
	if err := readStrictJSON(*requestPath, &request); err != nil {
		return errors.New("read collection request")
	}
	request.CleanupTimeout = *cleanupTimeout
	request.PollInterval = *pollInterval
	var resultObservation velero118.DataUploadResultObservation
	if err := readStrictJSON(*resultObservationPath, &resultObservation); err != nil {
		return errors.New("read DataUploadResult observation")
	}
	defer zeroBytes(resultObservation.Object)
	request.DataUploadResultObservation = &resultObservation
	var baseline restoreproof.SourceBaseline
	if err := readStrictJSON(*baselinePath, &baseline); err != nil {
		return errors.New("read source baseline")
	}
	archive, err := os.Open(filepath.Clean(*archivePath))
	if err != nil {
		return errors.New("open Velero BackupContents")
	}
	archivedDataUpload, archiveErr := velero118.ReadArchivedDataUpload(archive, request.VeleroNamespace, request.DataUploadName)
	closeErr := archive.Close()
	if archiveErr != nil || closeErr != nil {
		zeroBytes(archivedDataUpload)
		return errors.New("read exact archived DataUpload")
	}
	defer zeroBytes(archivedDataUpload)
	reader, err := newCollectorKubectlReader(*kubectl, *kubeconfigFD)
	if err != nil {
		return err
	}
	defer reader.Close()
	probeObserver, err := velero118.NewExecProbeObserverForKubectlReader(*probeAdapterPath, reader)
	if err != nil {
		return err
	}
	defer probeObserver.Close()
	providerObserver, err := velero118.NewExecBackendObserver(*providerAdapterPath)
	if err != nil {
		return err
	}
	defer providerObserver.Close()
	cleanupBarrier := fileCleanupBarrier{path: *cleanupReadyPath}
	receipt, err := velero118.CollectCSIDataMoverVolumeLineage(ctx, reader, probeObserver, providerObserver, cleanupBarrier, request, baseline, archivedDataUpload, velero118.SystemClock())
	if err != nil {
		return err
	}
	if err := writePrivateJSON(*outputPath, receipt); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "status=receipt_written")
	return nil
}

func newCollectorKubectlReader(binary string, kubeconfigFD int) (*velero118.KubectlReader, error) {
	if kubeconfigFD == -1 {
		return velero118.NewKubectlReader(binary)
	}
	if kubeconfigFD < 3 {
		return nil, errors.New("kubeconfig pipe descriptor is invalid")
	}
	return velero118.NewKubectlReaderFromKubeconfigFD(binary, kubeconfigFD)
}

func runVerify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	receiptPath := flags.String("receipt", "", "private unsigned receipt JSON")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *receiptPath == "" {
		return errors.New("invalid verify arguments")
	}
	var receipt restoreproof.VolumeReceipt
	if err := readStrictJSON(*receiptPath, &receipt); err != nil {
		return errors.New("read restore proof receipt")
	}
	if err := restoreproof.ValidateCSIDataMoverVolumeReceipt(&receipt); err != nil {
		return errors.New("restore proof receipt is invalid")
	}
	_, _ = fmt.Fprintln(stdout, "status=verified")
	return nil
}

func readStrictJSON(path string, destination any) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := strictjson.Read(io.LimitReader(file, maxPrivateArtifactBytes+1))
	if err != nil {
		return err
	}
	defer zeroBytes(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("decode private JSON artifact")
	}
	return nil
}

func writePrivateJSON(path string, value any) error {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return errors.New("private artifact path is invalid")
	}
	directory := filepath.Dir(clean)
	file, err := os.CreateTemp(directory, ".cloudring-private-artifact-*")
	if err != nil {
		return errors.New("create private artifact temporary file")
	}
	temporaryPath := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("protect private artifact temporary file")
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return errors.New("encode private artifact")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync private artifact")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private artifact")
	}
	// Link publishes a fully written inode atomically and fails if the target
	// already exists. The temporary file is created in the same directory.
	if err := os.Link(temporaryPath, clean); err != nil {
		return errors.New("publish private artifact without overwrite")
	}
	return nil
}

type fileCleanupBarrier struct{ path string }

type fileObservationReadyBarrier struct{ path string }

func (barrier fileObservationReadyBarrier) ReadyForRestore(ctx context.Context, notice velero118.DataUploadResultObservationReady) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parsed, timeErr := time.Parse(time.RFC3339Nano, notice.WatchStartedAt)
	_, digestErr := hex.DecodeString(notice.RequestSHA256)
	if notice.SchemaVersion != velero118.DataUploadResultObservationReadySchemaVersion || notice.Status != velero118.DataUploadResultObservationReadyStatus ||
		timeErr != nil || parsed.UTC().Format(time.RFC3339Nano) != notice.WatchStartedAt || len(notice.RequestSHA256) != 64 || digestErr != nil {
		return errors.New("DataUploadResult observation readiness notice is invalid")
	}
	return writePrivateJSON(barrier.path, notice)
}

func (barrier fileCleanupBarrier) ReadyForCleanup(ctx context.Context, notice velero118.CleanupReady) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parsed, timeErr := time.Parse(time.RFC3339Nano, notice.ReadyAt)
	_, digestErr := hex.DecodeString(notice.CleanupRunNonceSHA256)
	if notice.SchemaVersion != velero118.CleanupReadySchemaVersion || notice.Status != velero118.CleanupReadyStatus ||
		timeErr != nil || parsed.UTC().Format(time.RFC3339Nano) != notice.ReadyAt || len(notice.CleanupRunNonceSHA256) != 64 || digestErr != nil {
		return errors.New("cleanup readiness notice is invalid")
	}
	return writePrivateJSON(barrier.path, notice)
}

func samePath(left, right string) bool {
	leftDestination, leftErr := canonicalDestination(left)
	rightDestination, rightErr := canonicalDestination(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	if leftDestination == rightDestination {
		return true
	}
	return filepath.Dir(leftDestination) == filepath.Dir(rightDestination) && strings.EqualFold(filepath.Base(leftDestination), filepath.Base(rightDestination))
}

func canonicalDestination(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func validateNewArtifactDestinations(paths ...string) error {
	destinations := make([]string, 0, len(paths))
	for _, path := range paths {
		destination, err := canonicalDestination(path)
		if err != nil {
			return err
		}
		// #nosec G703 -- this is an intentional fail-closed lstat of a caller-selected local output destination.
		if _, err := os.Lstat(destination); err == nil || !os.IsNotExist(err) {
			return errors.New("artifact destination already exists or cannot be inspected")
		}
		for _, previous := range destinations {
			if destination == previous || filepath.Dir(destination) == filepath.Dir(previous) && strings.EqualFold(filepath.Base(destination), filepath.Base(previous)) {
				return errors.New("artifact destinations overlap")
			}
		}
		destinations = append(destinations, destination)
	}
	return nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
