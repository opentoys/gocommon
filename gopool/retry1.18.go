//go:build go1.18
// +build go1.18

package gopool

// Frok https://github.com/avast/retry-go

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

// Function signature of retryable function
type RetryableFunc func() error

// Function signature of retryable function with data
type RetryableFuncWithData[T any] func() (T, error)

// Default timer is a wrapper around time.After
type timerImpl struct{}

func (t *timerImpl) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

func Retry(retryableFunc RetryableFunc, opts ...RetryOption) error {
	retryableFuncWithData := func() (any, error) {
		return nil, retryableFunc()
	}

	_, err := RetryWithData(retryableFuncWithData, opts...)
	return err
}

func RetryWithData[T any](retryableFunc RetryableFuncWithData[T], opts ...RetryOption) (T, error) {
	var n uint
	var emptyT T

	// default
	config := newDefaultRetryConfig()

	// apply opts
	for _, opt := range opts {
		opt(config)
	}

	if err := config.context.Err(); err != nil {
		return emptyT, err
	}

	// Setting attempts to 0 means we'll retry until we succeed
	var lastErr error
	if config.attempts == 0 {
		for {
			t, err := retryableFunc()
			if err == nil {
				return t, nil
			}

			if !IsRecoverableRetry(err) {
				return emptyT, err
			}

			if !config.retryIf(err) {
				return emptyT, err
			}

			lastErr = err

			n++
			config.onRetry(n, err)
			select {
			case <-config.timer.After(delayRetry(config, n, err)):
			case <-config.context.Done():
				if config.wrapContextErrorWithLastError {
					return emptyT, RetryError{config.context.Err(), lastErr}
				}
				return emptyT, config.context.Err()
			}
		}
	}

	errorLog := RetryError{}

	attemptsForError := make(map[error]uint, len(config.attemptsForError))
	for err, attempts := range config.attemptsForError {
		attemptsForError[err] = attempts
	}

	shouldRetry := true
	for shouldRetry {
		t, err := retryableFunc()
		if err == nil {
			return t, nil
		}

		errorLog = append(errorLog, unpackUnrecoverableRetry(err))

		if !config.retryIf(err) {
			break
		}

		config.onRetry(n, err)

		for errToCheck, attempts := range attemptsForError {
			if errors.Is(err, errToCheck) {
				attempts--
				attemptsForError[errToCheck] = attempts
				shouldRetry = shouldRetry && attempts > 0
			}
		}

		// if this is last attempt - don't wait
		if n == config.attempts-1 {
			break
		}

		select {
		case <-config.timer.After(delayRetry(config, n, err)):
		case <-config.context.Done():
			if config.lastErrorOnly {
				return emptyT, config.context.Err()
			}

			return emptyT, append(errorLog, config.context.Err())
		}

		n++
		shouldRetry = shouldRetry && n < config.attempts
	}

	if config.lastErrorOnly {
		return emptyT, errorLog.Unwrap()
	}
	return emptyT, errorLog
}

func newDefaultRetryConfig() *Config {
	return &Config{
		attempts:         uint(10),
		attemptsForError: make(map[error]uint),
		delay:            100 * time.Millisecond,
		maxJitter:        100 * time.Millisecond,
		onRetry:          func(n uint, err error) {},
		retryIf:          IsRecoverableRetry,
		delayType:        CombineDelay(BackOffDelay, RandomDelay),
		lastErrorOnly:    false,
		context:          context.Background(),
		timer:            &timerImpl{},
	}
}

// Error type represents list of errors in retry
type RetryError []error

// Error method return string representation of Error
// It is an implementation of error interface
func (e RetryError) Error() string {
	logWithNumber := make([]string, len(e))
	for i, l := range e {
		if l != nil {
			logWithNumber[i] = fmt.Sprintf("#%d: %s", i+1, l.Error())
		}
	}

	return fmt.Sprintf("All attempts fail:\n%s", strings.Join(logWithNumber, "\n"))
}

func (e RetryError) Is(target error) bool {
	for _, v := range e {
		if errors.Is(v, target) {
			return true
		}
	}
	return false
}

func (e RetryError) As(target interface{}) bool {
	for _, v := range e {
		if errors.As(v, target) {
			return true
		}
	}
	return false
}

/*
Unwrap the last error for compatibility with `errors.Unwrap()`.
When you need to unwrap all errors, you should use `WrappedErrors()` instead.

	err := Retry(
		func() error {
			return errors.New("original error")
		},
		Attempts(1),
	)

	fmt.Println(errors.Unwrap(err)) # "original error" is printed

Added in version 4.2.0.
*/
func (e RetryError) Unwrap() error {
	return e[len(e)-1]
}

// WrappedErrors returns the list of errors that this Error is wrapping.
// It is an implementation of the `errwrap.Wrapper` interface
// in package [errwrap](https://github.com/hashicorp/errwrap) so that
// `retry.Error` can be used with that library.
func (e RetryError) WrappedErrors() []error {
	return e
}

type unrecoverableRetryError struct {
	error
}

func (e unrecoverableRetryError) Error() string {
	if e.error == nil {
		return "unrecoverable error"
	}
	return e.error.Error()
}

func (e unrecoverableRetryError) Unwrap() error {
	return e.error
}

// Unrecoverable wraps an error in `unrecoverableError` struct
func UnrecoverableRetry(err error) error {
	return unrecoverableRetryError{err}
}

// IsRecoverable checks if error is an instance of `unrecoverableError`
func IsRecoverableRetry(err error) bool {
	return !errors.Is(err, unrecoverableRetryError{})
}

// Adds support for errors.Is usage on unrecoverableError
func (unrecoverableRetryError) Is(err error) bool {
	_, isUnrecoverable := err.(unrecoverableRetryError)
	return isUnrecoverable
}

func unpackUnrecoverableRetry(err error) error {
	if unrecoverable, isUnrecoverable := err.(unrecoverableRetryError); isUnrecoverable {
		return unrecoverable.error
	}

	return err
}

func delayRetry(config *Config, n uint, err error) time.Duration {
	delayTime := config.delayType(n, err, config)
	if config.maxDelay > 0 && delayTime > config.maxDelay {
		delayTime = config.maxDelay
	}

	return delayTime
}

// ========================
//
// ========================

// Function signature of retry if function
type RetryIfFunc func(error) bool

// Function signature of OnRetry function
// n = count of attempts
type OnRetryFunc func(n uint, err error)

// DelayTypeFunc is called to return the next delay to wait after the retriable function fails on `err` after `n` attempts.
type DelayTypeFunc func(n uint, err error, config *Config) time.Duration

// Timer represents the timer used to track time for a retry.
type RetryTimer interface {
	After(time.Duration) <-chan time.Time
}

type Config struct {
	attempts                      uint
	attemptsForError              map[error]uint
	delay                         time.Duration
	maxDelay                      time.Duration
	maxJitter                     time.Duration
	onRetry                       OnRetryFunc
	retryIf                       RetryIfFunc
	delayType                     DelayTypeFunc
	lastErrorOnly                 bool
	context                       context.Context
	timer                         RetryTimer
	wrapContextErrorWithLastError bool

	maxBackOffN uint
}

// Option represents an option for retry.
type RetryOption func(*Config)

func emptyRetryOption(c *Config) {}

// return the direct last error that came from the retried function
// default is false (return wrapped errors with everything)
func LastErrorOnly(lastErrorOnly bool) RetryOption {
	return func(c *Config) {
		c.lastErrorOnly = lastErrorOnly
	}
}

// Attempts set count of retry. Setting to 0 will retry until the retried function succeeds.
// default is 10
func RetryAttempts(attempts uint) RetryOption {
	return func(c *Config) {
		c.attempts = attempts
	}
}

// AttemptsForError sets count of retry in case execution results in given `err`
// Retries for the given `err` are also counted against total retries.
// The retry will stop if any of given retries is exhausted.
//
// added in 4.3.0
func RetryAttemptsForError(attempts uint, err error) RetryOption {
	return func(c *Config) {
		c.attemptsForError[err] = attempts
	}
}

// Delay set delay between retry
// default is 100ms
func RetryDelay(delay time.Duration) RetryOption {
	return func(c *Config) {
		c.delay = delay
	}
}

// MaxDelay set maximum delay between retry
// does not apply by default
func RetryMaxDelay(maxDelay time.Duration) RetryOption {
	return func(c *Config) {
		c.maxDelay = maxDelay
	}
}

// MaxJitter sets the maximum random Jitter between retries for RandomDelay
func RetryMaxJitter(maxJitter time.Duration) RetryOption {
	return func(c *Config) {
		c.maxJitter = maxJitter
	}
}

// DelayType set type of the delay between retries
// default is BackOff
func RetryDelayType(delayType DelayTypeFunc) RetryOption {
	if delayType == nil {
		return emptyRetryOption
	}
	return func(c *Config) {
		c.delayType = delayType
	}
}

// BackOffDelay is a DelayType which increases delay between consecutive retries
func BackOffDelay(n uint, _ error, config *Config) time.Duration {
	// 1 << 63 would overflow signed int64 (time.Duration), thus 62.
	const max uint = 62

	if config.maxBackOffN == 0 {
		if config.delay <= 0 {
			config.delay = 1
		}

		config.maxBackOffN = max - uint(math.Floor(math.Log2(float64(config.delay))))
	}

	if n > config.maxBackOffN {
		n = config.maxBackOffN
	}

	return config.delay << n
}

// FixedDelay is a DelayType which keeps delay the same through all iterations
func FixedDelay(_ uint, _ error, config *Config) time.Duration {
	return config.delay
}

// RandomDelay is a DelayType which picks a random delay up to config.maxJitter
func RandomDelay(_ uint, _ error, config *Config) time.Duration {
	return time.Duration(rand.Int63n(int64(config.maxJitter)))
}

// CombineDelay is a DelayType the combines all of the specified delays into a new DelayTypeFunc
func CombineDelay(delays ...DelayTypeFunc) DelayTypeFunc {
	const maxInt64 = uint64(math.MaxInt64)

	return func(n uint, err error, config *Config) time.Duration {
		var total uint64
		for _, delay := range delays {
			total += uint64(delay(n, err, config))
			if total > maxInt64 {
				total = maxInt64
			}
		}

		return time.Duration(total)
	}
}

// OnRetry function callback are called each retry
//
// log each retry example:
//
//	retry.Retry(
//		func() error {
//			return errors.New("some error")
//		},
//		retry.OnRetry(func(n uint, err error) {
//			log.Printf("#%d: %s\n", n, err)
//		}),
//	)
func OnRetry(onRetry OnRetryFunc) RetryOption {
	if onRetry == nil {
		return emptyRetryOption
	}
	return func(c *Config) {
		c.onRetry = onRetry
	}
}

// RetryIf controls whether a retry should be attempted after an error
// (assuming there are any retry attempts remaining)
//
// skip retry if special error example:
//
//	retry.Retry(
//		func() error {
//			return errors.New("special error")
//		},
//		retry.RetryIf(func(err error) bool {
//			if err.Error() == "special error" {
//				return false
//			}
//			return true
//		})
//	)
//
// By default RetryIf stops execution if the error is wrapped using `retry.Unrecoverable`,
// so above example may also be shortened to:
//
//	retry.Retry(
//		func() error {
//			return retry.Unrecoverable(errors.New("special error"))
//		}
//	)
func RetryIf(retryIf RetryIfFunc) RetryOption {
	if retryIf == nil {
		return emptyRetryOption
	}
	return func(c *Config) {
		c.retryIf = retryIf
	}
}

// Context allow to set context of retry
// default are Background context
//
// example of immediately cancellation (maybe it isn't the best example, but it describes behavior enough; I hope)
//
//	ctx, cancel := context.WithCancel(context.Background())
//	cancel()
//
//	retry.Retry(
//		func() error {
//			...
//		},
//		retry.Context(ctx),
//	)
func RetryContext(ctx context.Context) RetryOption {
	return func(c *Config) {
		c.context = ctx
	}
}

// WithTimer provides a way to swap out timer module implementations.
// This primarily is useful for mocking/testing, where you may not want to explicitly wait for a set duration
// for retries.
//
// example of augmenting time.After with a print statement
//
//	type struct MyTimer {}
//
//	func (t *MyTimer) After(d time.Duration) <- chan time.Time {
//	    fmt.Print("Timer called!")
//	    return time.After(d)
//	}
//
//	retry.Retry(
//	    func() error { ... },
//		   retry.WithTimer(&MyTimer{})
//	)
func WithRetryTimer(t RetryTimer) RetryOption {
	return func(c *Config) {
		c.timer = t
	}
}

// WrapContextErrorWithLastError allows the context error to be returned wrapped with the last error that the
// retried function returned. This is only applicable when Attempts is set to 0 to retry indefinitly and when
// using a context to cancel / timeout
//
// default is false
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	retry.Retry(
//		func() error {
//			...
//		},
//		retry.Context(ctx),
//		retry.Attempts(0),
//		retry.WrapContextErrorWithLastError(true),
//	)
func WrapContextRetryErrorWithLastError(wrapContextErrorWithLastError bool) RetryOption {
	return func(c *Config) {
		c.wrapContextErrorWithLastError = wrapContextErrorWithLastError
	}
}
