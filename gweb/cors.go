/*
Package cors is net/http handler to handle CORS related requests
as defined by http://www.w3.org/TR/cors/
*/
package gweb // Fork github.com/rs/cors

import (
	"net/http"
	"strconv"
	"strings"
)

var cors_headerVaryOrigin = []string{"Origin"}
var cors_headerOriginAll = []string{"*"}
var cors_headerTrue = []string{"true"}

// CORSOptions is a configuration container to setup the CORS middleware.
type CORSOptions struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters
	// (i.e.: http://*.domain.com). Usage of wildcards implies a small performance penalty.
	// Only one wildcard can be used per origin.
	// Default value is ["*"]
	AllowedOrigins []string
	// AllowOriginFunc is a custom function to validate the origin. It take the
	// origin as argument and returns true if allowed or false otherwise. If
	// this option is set, the content of `AllowedOrigins` is ignored.
	AllowOriginFunc func(origin string) bool
	// AllowOriginRequestFunc is a custom function to validate the origin. It
	// takes the HTTP Request object and the origin as argument and returns true
	// if allowed or false otherwise. If headers are used take the decision,
	// consider using AllowOriginVaryRequestFunc instead. If this option is set,
	// the content of `AllowedOrigins`, `AllowOriginFunc` are ignored.
	AllowOriginRequestFunc func(r *http.Request, origin string) bool
	// AllowOriginVaryRequestFunc is a custom function to validate the origin.
	// It takes the HTTP Request object and the origin as argument and returns
	// true if allowed or false otherwise with a list of headers used to take
	// that decision if any so they can be added to the Vary header. If this
	// option is set, the content of `AllowedOrigins`, `AllowOriginFunc` and
	// `AllowOriginRequestFunc` are ignored.
	AllowOriginVaryRequestFunc func(r *http.Request, origin string) (bool, []string)
	// AllowedMethods is a list of methods the client is allowed to use with
	// cross-domain requests. Default value is simple methods (HEAD, GET and POST).
	AllowedMethods []string
	// AllowedHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	// If the special "*" value is present in the list, all headers will be allowed.
	// Default value is [].
	AllowedHeaders []string
	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	ExposedHeaders []string
	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached. Default value is 0, which stands for no
	// Access-Control-Max-Age header to be sent back, resulting in browsers
	// using their default value (5s by spec). If you need to force a 0 max-age,
	// set `MaxAge` to a negative value (ie: -1).
	MaxAge int
	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool
	// AllowPrivateNetwork indicates whether to accept cross-origin requests over a
	// private network.
	AllowPrivateNetwork bool
	// OptionsPassthrough instructs preflight to let other potential next handlers to
	// process the OPTIONS method. Turn this on if your application handles OPTIONS.
	OptionsPassthrough bool
	// Provides a status code to use for successful OPTIONS requests.
	// Default value is http.StatusNoContent (204).
	OptionsSuccessStatus int
}

// Cors http handler
type Cors struct {
	allowedOrigins       []string        // Normalized list of plain allowed origins
	allowedWOrigins      []cors_wildcard // List of allowed origins containing wildcards
	allowedHeaders       []string        // Normalized list of allowed headers
	allowedMethods       []string        // Normalized list of allowed methods
	exposedHeaders       []string        // Pre-computed normalized list of exposed headers
	maxAge               []string        // Pre-computed maxAge header value
	allowedOriginsAll    bool            // Set to true when allowed origins contains a "*"
	allowedHeadersAll    bool            // Set to true when allowed headers contains a "*"
	optionsSuccessStatus int             // Status code to use for successful OPTIONS requests. Default value is http.StatusNoContent (204).
	allowCredentials     bool            // AllowCredentials indicates whether the request can include user credentials like cookies, HTTP authentication or client side SSL certificates.
	allowPrivateNetwork  bool            // AllowPrivateNetwork indicates whether to accept cross-origin requests over a private network.
	optionPassthrough    bool            // OptionsPassthrough instructs preflight to let other potential next handlers to process the OPTIONS method. Turn this on if your application handles OPTIONS.
	preflightVary        []string

	allowOriginFunc func(r *http.Request, origin string) (bool, []string) // Optional origin validator function
}

// New creates a new Cors handler with the provided options.
func NewCORS(options *CORSOptions) *Cors {
	c := &Cors{
		allowCredentials:    options.AllowCredentials,
		allowPrivateNetwork: options.AllowPrivateNetwork,
		optionPassthrough:   options.OptionsPassthrough,
	}

	// Allowed origins
	switch {
	case options.AllowOriginVaryRequestFunc != nil:
		c.allowOriginFunc = options.AllowOriginVaryRequestFunc
	case options.AllowOriginRequestFunc != nil:
		c.allowOriginFunc = func(r *http.Request, origin string) (bool, []string) {
			return options.AllowOriginRequestFunc(r, origin), nil
		}
	case options.AllowOriginFunc != nil:
		c.allowOriginFunc = func(r *http.Request, origin string) (bool, []string) {
			return options.AllowOriginFunc(origin), nil
		}
	case len(options.AllowedOrigins) == 0:
		if c.allowOriginFunc == nil {
			// Default is all origins
			c.allowedOriginsAll = true
		}
	default:
		c.allowedOrigins = []string{}
		c.allowedWOrigins = []cors_wildcard{}
		for _, origin := range options.AllowedOrigins {
			// Note: for origins matching, the spec requires a case-sensitive matching.
			// As it may error prone, we chose to ignore the spec here.
			origin = strings.ToLower(origin)
			if origin == "*" {
				// If "*" is present in the list, turn the whole list into a match all
				c.allowedOriginsAll = true
				c.allowedOrigins = nil
				c.allowedWOrigins = nil
				break
			} else if i := strings.IndexByte(origin, '*'); i >= 0 {
				// Split the origin in two: start and end string without the *
				w := cors_wildcard{origin[0:i], origin[i+1:]}
				c.allowedWOrigins = append(c.allowedWOrigins, w)
			} else {
				c.allowedOrigins = append(c.allowedOrigins, origin)
			}
		}
	}

	// Allowed Headers
	if len(options.AllowedHeaders) == 0 {
		// Use sensible defaults
		c.allowedHeaders = []string{"Accept", "Content-Type", "X-Requested-With"}
	} else {
		c.allowedHeaders = cors_convert(options.AllowedHeaders, http.CanonicalHeaderKey)
		for _, h := range options.AllowedHeaders {
			if h == "*" {
				c.allowedHeadersAll = true
				c.allowedHeaders = nil
				break
			}
		}
	}

	// Allowed Methods
	if len(options.AllowedMethods) == 0 {
		// Default is spec's "simple" methods
		c.allowedMethods = []string{http.MethodGet, http.MethodPost, http.MethodHead}
	} else {
		c.allowedMethods = options.AllowedMethods
	}

	// Options Success Status Code
	if options.OptionsSuccessStatus == 0 {
		c.optionsSuccessStatus = http.StatusNoContent
	} else {
		c.optionsSuccessStatus = options.OptionsSuccessStatus
	}

	// Pre-compute exposed headers header value
	if len(options.ExposedHeaders) > 0 {
		c.exposedHeaders = []string{strings.Join(cors_convert(options.ExposedHeaders, http.CanonicalHeaderKey), ", ")}
	}

	// Pre-compute prefight Vary header to save allocations
	if c.allowPrivateNetwork {
		c.preflightVary = []string{"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"}
	} else {
		c.preflightVary = []string{"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"}
	}

	// Precompute max-age
	if options.MaxAge > 0 {
		c.maxAge = []string{strconv.Itoa(options.MaxAge)}
	} else if options.MaxAge < 0 {
		c.maxAge = []string{"0"}
	}

	return c
}

// AllowAll create a new Cors handler with permissive configuration allowing all
// origins with all standard methods with any header and credentials.
var AllowAll = &CORSOptions{
	AllowedOrigins: []string{"*"},
	AllowedMethods: []string{
		http.MethodHead,
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	},
	AllowedHeaders:   []string{"*"},
	AllowCredentials: false,
}

func DefaulteCORS(opts *CORSOptions) Handler {
	var c *Cors
	if opts != nil {
		c = NewCORS(opts)
	} else {
		c = NewCORS(AllowAll)
	}
	return func(ctx *Context) {
		if ctx.Request.Method == http.MethodOptions && ctx.Request.Header.Get("Access-Control-Request-Method") != "" {
			c.handlePreflight(ctx.Writer, ctx.Request)
			ctx.Writer.WriteHeader(c.optionsSuccessStatus)
		} else {
			c.handleActualRequest(ctx.Writer, ctx.Request)
		}
	}
}

// handlePreflight handles pre-flight CORS requests
func (c *Cors) handlePreflight(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	origin := r.Header.Get("Origin")

	if r.Method != http.MethodOptions {
		return
	}
	// Always set Vary headers
	// see https://github.com/rs/cors/issues/10,
	//     https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001
	if vary, found := headers["Vary"]; found {
		headers["Vary"] = append(vary, c.preflightVary[0])
	} else {
		headers["Vary"] = c.preflightVary
	}
	allowed, additionalVaryHeaders := c.isOriginAllowed(r, origin)
	if len(additionalVaryHeaders) > 0 {
		headers.Add("Vary", strings.Join(cors_convert(additionalVaryHeaders, http.CanonicalHeaderKey), ", "))
	}

	if origin == "" {
		return
	}
	if !allowed {
		return
	}

	reqMethod := r.Header.Get("Access-Control-Request-Method")
	if !c.isMethodAllowed(reqMethod) {
		return
	}
	reqHeadersRaw := r.Header["Access-Control-Request-Headers"]
	reqHeaders, reqHeadersEdited := cors_convertDidCopy(cors_splitHeaderValues(reqHeadersRaw), http.CanonicalHeaderKey)
	if !c.areHeadersAllowed(reqHeaders) {
		return
	}
	if c.allowedOriginsAll {
		headers["Access-Control-Allow-Origin"] = cors_headerOriginAll
	} else {
		headers["Access-Control-Allow-Origin"] = r.Header["Origin"]
	}
	// Spec says: Since the list of methods can be unbounded, simply returning the method indicated
	// by Access-Control-Request-Method (if supported) can be enough
	headers["Access-Control-Allow-Methods"] = r.Header["Access-Control-Request-Method"]
	if len(reqHeaders) > 0 {
		// Spec says: Since the list of headers can be unbounded, simply returning supported headers
		// from Access-Control-Request-Headers can be enough
		if reqHeadersEdited || len(reqHeaders) != len(reqHeadersRaw) {
			headers.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
		} else {
			headers["Access-Control-Allow-Headers"] = reqHeadersRaw
		}
	}
	if c.allowCredentials {
		headers["Access-Control-Allow-Credentials"] = cors_headerTrue
	}
	if c.allowPrivateNetwork && r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		headers["Access-Control-Allow-Private-Network"] = cors_headerTrue
	}
	if len(c.maxAge) > 0 {
		headers["Access-Control-Max-Age"] = c.maxAge
	}
}

// handleActualRequest handles simple cross-origin requests, actual request or redirects
func (c *Cors) handleActualRequest(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	origin := r.Header.Get("Origin")

	allowed, additionalVaryHeaders := c.isOriginAllowed(r, origin)

	// Always set Vary, see https://github.com/rs/cors/issues/10
	if vary, found := headers["Vary"]; found {
		headers["Vary"] = append(vary, cors_headerVaryOrigin[0])
	} else {
		headers["Vary"] = cors_headerVaryOrigin
	}
	if len(additionalVaryHeaders) > 0 {
		headers.Add("Vary", strings.Join(cors_convert(additionalVaryHeaders, http.CanonicalHeaderKey), ", "))
	}
	if origin == "" {
		return
	}
	if !allowed {
		return
	}

	// Note that spec does define a way to specifically disallow a simple method like GET or
	// POST. Access-Control-Allow-Methods is only used for pre-flight requests and the
	// spec doesn't instruct to check the allowed methods for simple cross-origin requests.
	// We think it's a nice feature to be able to have control on those methods though.
	if !c.isMethodAllowed(r.Method) {
		return
	}
	if c.allowedOriginsAll {
		headers["Access-Control-Allow-Origin"] = cors_headerOriginAll
	} else {
		headers["Access-Control-Allow-Origin"] = r.Header["Origin"]
	}
	if len(c.exposedHeaders) > 0 {
		headers["Access-Control-Expose-Headers"] = c.exposedHeaders
	}
	if c.allowCredentials {
		headers["Access-Control-Allow-Credentials"] = cors_headerTrue
	}
}

// isOriginAllowed checks if a given origin is allowed to perform cross-domain requests
// on the endpoint
func (c *Cors) isOriginAllowed(r *http.Request, origin string) (allowed bool, varyHeaders []string) {
	if c.allowOriginFunc != nil {
		return c.allowOriginFunc(r, origin)
	}
	if c.allowedOriginsAll {
		return true, nil
	}
	origin = strings.ToLower(origin)
	for _, o := range c.allowedOrigins {
		if o == origin {
			return true, nil
		}
	}
	for _, w := range c.allowedWOrigins {
		if w.match(origin) {
			return true, nil
		}
	}
	return false, nil
}

// isMethodAllowed checks if a given method can be used as part of a cross-domain request
// on the endpoint
func (c *Cors) isMethodAllowed(method string) bool {
	if len(c.allowedMethods) == 0 {
		// If no method allowed, always return false, even for preflight request
		return false
	}
	if method == http.MethodOptions {
		// Always allow preflight requests
		return true
	}
	for _, m := range c.allowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

// areHeadersAllowed checks if a given list of headers are allowed to used within
// a cross-domain request.
func (c *Cors) areHeadersAllowed(requestedHeaders []string) bool {
	if c.allowedHeadersAll || len(requestedHeaders) == 0 {
		return true
	}
	for _, header := range requestedHeaders {
		found := false
		for _, h := range c.allowedHeaders {
			if h == header {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type cors_converter func(string) string

type cors_wildcard struct {
	prefix string
	suffix string
}

func (w cors_wildcard) match(s string) bool {
	return len(s) >= len(w.prefix)+len(w.suffix) && strings.HasPrefix(s, w.prefix) && strings.HasSuffix(s, w.suffix)
}

// split compounded header values ["foo, bar", "baz"] -> ["foo", "bar", "baz"]
func cors_splitHeaderValues(values []string) []string {
	out := values
	copied := false
	for i, v := range values {
		needsSplit := strings.IndexByte(v, ',') != -1
		if !copied {
			if needsSplit {
				split := strings.Split(v, ",")
				out = make([]string, i, len(values)+len(split)-1)
				copy(out, values[:i])
				for _, s := range split {
					out = append(out, strings.TrimSpace(s))
				}
				copied = true
			}
		} else {
			if needsSplit {
				split := strings.Split(v, ",")
				for _, s := range split {
					out = append(out, strings.TrimSpace(s))
				}
			} else {
				out = append(out, v)
			}
		}
	}
	return out
}

// cors_convert converts a list of string using the passed converter function
func cors_convert(s []string, c cors_converter) []string {
	out, _ := cors_convertDidCopy(s, c)
	return out
}

// cors_convertDidCopy is same as convert but returns true if it copied the slice
func cors_convertDidCopy(s []string, c cors_converter) ([]string, bool) {
	out := s
	copied := false
	for i, v := range s {
		if !copied {
			v2 := c(v)
			if v2 != v {
				out = make([]string, len(s))
				copy(out, s[:i])
				out[i] = v2
				copied = true
			}
		} else {
			out[i] = c(v)
		}
	}
	return out, copied
}
