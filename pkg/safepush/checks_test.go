// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestVerifyChecksAcceptsExactSuccessfulJobs(t *testing.T) {
	t.Parallel()
	for _, length := range []int{40, 64} {
		head := strings.Repeat("ab", length/2)
		t.Run(head, func(t *testing.T) {
			t.Parallel()
			required, observations := successfulChecks(head)
			// API order is not evidence, and the same job name in two verified
			// workflows denotes two distinct requirements.
			slices.Reverse(observations)
			beforeRequired := slices.Clone(required)
			beforeObserved := slices.Clone(observations)
			if err := VerifyChecks(head, required, observations); err != nil {
				t.Fatalf("complete successful evidence rejected: %v", err)
			}
			if !reflect.DeepEqual(required, beforeRequired) || !reflect.DeepEqual(observations, beforeObserved) {
				t.Fatal("verification mutated its inputs")
			}
		})
	}
}

func TestVerifyChecksRejectsIncompleteOrAmbiguousEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func([]CheckIdentity, []CheckObservation) ([]CheckIdentity, []CheckObservation)
		want   error
	}{
		{
			name: "empty policy cannot disable admission",
			change: func(_ []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				return nil, observations
			},
			want: ErrNoRequiredChecks,
		},
		{
			name: "no observations",
			change: func(required []CheckIdentity, _ []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				return required, nil
			},
			want: ErrMissingCheck,
		},
		{
			name: "one missing job despite other green jobs",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				return required, observations[1:]
			},
			want: ErrMissingCheck,
		},
		{
			name: "same job name from another workflow is not evidence",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				observations[0].Check.Source = ".github/workflows/other.yml@" + strings.Repeat("cd", 20)
				return required, observations
			},
			want: ErrUnexpectedCheck,
		},
		{
			name: "different workflow revision is not evidence",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				observations[0].Check.Source = ".github/workflows/go.yml@" + strings.Repeat("ef", 20)
				return required, observations
			},
			want: ErrUnexpectedCheck,
		},
		{
			name: "green result for stale head",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				observations[0].HeadSHA = strings.Repeat("cd", 20)
				return required, observations
			},
			want: ErrHeadMismatch,
		},
		{
			name: "observation lacks head",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				observations[0].HeadSHA = ""
				return required, observations
			},
			want: ErrHeadMismatch,
		},
		{
			name: "duplicate policy job",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				return append(required, required[0]), observations
			},
			want: ErrDuplicateRequiredCheck,
		},
		{
			name: "duplicate successful observations",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				return required, append(observations, observations[0])
			},
			want: ErrDuplicateObservation,
		},
		{
			name: "green attempt cannot hide failed attempt",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				failed := observations[0]
				failed.Conclusion = "failure"
				return required, append(observations, failed)
			},
			want: ErrDuplicateObservation,
		},
		{
			name: "unconfigured successful job",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				extra := observations[0]
				extra.Check.Job = "new test suite"
				return required, append(observations, extra)
			},
			want: ErrUnexpectedCheck,
		},
		{
			name: "unconfigured failed job cannot be ignored",
			change: func(required []CheckIdentity, observations []CheckObservation) ([]CheckIdentity, []CheckObservation) {
				extra := observations[0]
				extra.Check.Job = "new test suite"
				extra.Conclusion = "failure"
				return required, append(observations, extra)
			},
			want: ErrUnexpectedCheck,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			head := strings.Repeat("ab", 20)
			required, observations := successfulChecks(head)
			required, observations = test.change(required, observations)
			if err := VerifyChecks(head, required, observations); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			// Selecting whichever duplicate/defect the API returned first must
			// not change the decision or its category.
			slices.Reverse(required)
			slices.Reverse(observations)
			if err := VerifyChecks(head, required, observations); !errors.Is(err, test.want) {
				t.Fatalf("reordered input: got %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyChecksRejectsEveryNonSuccessState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status     string
		conclusion string
	}{
		{status: "pending"},
		{status: "queued"},
		{status: "running"},
		{status: "in_progress"},
		{status: "waiting"},
		{status: "requested"},
		{status: "cancelled"},
		{status: "skipped"},
		{status: "success"},
		{status: "completed"},
		{status: "completed", conclusion: "failure"},
		{status: "completed", conclusion: "cancelled"},
		{status: "completed", conclusion: "skipped"},
		{status: "completed", conclusion: "neutral"},
		{status: "completed", conclusion: "timed_out"},
		{status: "completed", conclusion: "action_required"},
		{status: "completed", conclusion: "stale"},
		{status: "completed", conclusion: "startup_failure"},
		{status: "completed", conclusion: "unknown"},
		{status: "in_progress", conclusion: "success"},
		{status: "unknown", conclusion: "success"},
		{status: "Completed", conclusion: "success"},
		{status: "completed", conclusion: "Success"},
		{status: " completed", conclusion: "success"},
		{status: "completed", conclusion: "success "},
		{},
	}
	for _, test := range tests {
		t.Run(test.status+"/"+test.conclusion, func(t *testing.T) {
			t.Parallel()
			head := strings.Repeat("ab", 20)
			required, observations := successfulChecks(head)
			observations[1].Status = test.status
			observations[1].Conclusion = test.conclusion
			if err := VerifyChecks(head, required, observations); !errors.Is(err, ErrCheckNotSuccessful) {
				t.Fatalf("non-success result: got %v, want %v", err, ErrCheckNotSuccessful)
			}
		})
	}
}

func TestVerifyChecksRejectsMalformedHeadEvenWhenObservationsAgree(t *testing.T) {
	t.Parallel()
	for _, head := range []string{
		"", "main", strings.Repeat("a", 39), strings.Repeat("a", 41),
		strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 40),
		strings.Repeat("A", 64), strings.Repeat("g", 40), strings.Repeat("0", 40),
		strings.Repeat("0", 64), strings.Repeat("a", 39) + "\n", strings.Repeat("a", 39) + " ",
	} {
		t.Run(head, func(t *testing.T) {
			t.Parallel()
			required, observations := successfulChecks(head)
			if err := VerifyChecks(head, required, observations); !errors.Is(err, ErrInvalidHeadSHA) {
				t.Fatalf("malformed candidate: got %v, want %v", err, ErrInvalidHeadSHA)
			}
		})
	}
}

func TestVerifyChecksRejectsMalformedIdentities(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", " ", "\u00a0", "\x00job", "job\n", "job\tname", "job\x7f", "\xff"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			for _, field := range []string{"source", "job"} {
				for _, location := range []string{"required", "observation"} {
					head := strings.Repeat("ab", 20)
					required, observations := successfulChecks(head)
					identity := &required[0]
					want := ErrInvalidRequiredCheck
					if location == "observation" {
						identity = &observations[0].Check
						want = ErrInvalidObservation
					}
					if field == "source" {
						identity.Source = value
					} else {
						identity.Job = value
					}
					if err := VerifyChecks(head, required, observations); !errors.Is(err, want) {
						t.Fatalf("%s %s: got %v, want %v", location, field, err, want)
					}
				}
			}
		})
	}
}

func TestVerifyChecksDoesNotNormalizeIdentities(t *testing.T) {
	t.Parallel()
	head := strings.Repeat("ab", 20)
	for _, pair := range [][2]string{
		{"unit", "Unit"},
		{"unit", " unit"},
		{"unit", "unit "},
		{"caf\u00e9", "cafe\u0301"},
	} {
		for _, field := range []string{"source", "job"} {
			required := []CheckIdentity{{Source: "workflow", Job: "unit"}}
			observation := CheckObservation{Check: required[0], HeadSHA: head, Status: "completed", Conclusion: "success"}
			if field == "source" {
				required[0].Source = pair[0]
				observation.Check.Source = pair[1]
			} else {
				required[0].Job = pair[0]
				observation.Check.Job = pair[1]
			}
			if err := VerifyChecks(head, required, []CheckObservation{observation}); !errors.Is(err, ErrUnexpectedCheck) {
				t.Fatalf("%s identity was normalized: got %v, want %v", field, err, ErrUnexpectedCheck)
			}
			// Meaningful spaces and Unicode are legal when their exact bytes
			// agree; validation must not silently rewrite a native job name.
			required[0] = observation.Check
			if err := VerifyChecks(head, required, []CheckObservation{observation}); err != nil {
				t.Fatalf("exact %s identity rejected: %v", field, err)
			}
		}
	}
}

func TestVerifyChecksPreservesIdentityFieldBoundaries(t *testing.T) {
	t.Parallel()
	head := strings.Repeat("ab", 20)
	required := []CheckIdentity{{Source: "workflow/a", Job: "b"}, {Source: "workflow", Job: "a/b"}}
	observations := []CheckObservation{
		{Check: required[0], HeadSHA: head, Status: "completed", Conclusion: "success"},
		{Check: required[1], HeadSHA: head, Status: "completed", Conclusion: "success"},
	}
	if err := VerifyChecks(head, required, observations); err != nil {
		t.Fatalf("distinct structured identities collided: %v", err)
	}
}

func TestVerifyChecksErrorsNeverEchoObservationValues(t *testing.T) {
	t.Parallel()
	head := strings.Repeat("ab", 20)
	required, observations := successfulChecks(head)
	const untrustedValue = "untrusted-response-marker"
	observations[0].HeadSHA = untrustedValue
	observations[0].Status = untrustedValue
	observations[0].Conclusion = untrustedValue
	observations[0].Check.Source = untrustedValue
	observations[0].Check.Job = untrustedValue
	err := VerifyChecks(head, required, observations)
	if !errors.Is(err, ErrHeadMismatch) {
		t.Fatalf("got %v, want %v", err, ErrHeadMismatch)
	}
	if strings.Contains(err.Error(), untrustedValue) {
		t.Fatal("error exposed raw observation data")
	}
}

func successfulChecks(head string) ([]CheckIdentity, []CheckObservation) {
	goWorkflow := ".github/workflows/go.yml@" + strings.Repeat("cd", 20)
	securityWorkflow := ".github/workflows/security.yml@" + strings.Repeat("ef", 20)
	required := []CheckIdentity{
		{Source: goWorkflow, Job: "unit (linux, go1.26.8)"},
		{Source: goWorkflow, Job: "race (linux, go1.26.8)"},
		{Source: securityWorkflow, Job: "unit (linux, go1.26.8)"},
	}
	observations := make([]CheckObservation, len(required))
	for index, check := range required {
		observations[index] = CheckObservation{Check: check, HeadSHA: head, Status: "completed", Conclusion: "success"}
	}
	return required, observations
}
