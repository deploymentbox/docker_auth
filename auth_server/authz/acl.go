package authz

import (
	"encoding/json"
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"
	"gopkg.in/redis.v3"
    "errors"
    "time"

	"github.com/golang/glog"
)

type ACL []ACLEntry

type ACLEntry struct {
	Match   *MatchConditions `yaml:"match"`
	Actions *[]string        `yaml:"actions,flow"`
	Comment *string          `yaml:"comment,omitempty"`
}

type MatchConditions struct {
	Account *string `yaml:"account,omitempty" json:"account,omitempty"`
	Type    *string `yaml:"type,omitempty" json:"type,omitempty"`
	Name    *string `yaml:"name,omitempty" json:"name,omitempty"`
	IP      *string `yaml:"ip,omitempty" json:"ip,omitempty"`
}

type aclAuthorizer struct {
	acl ACL
}

func validatePattern(p string) error {
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		_, err := regexp.Compile(p[1 : len(p)-1])
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %s", err)
		}
	}
	return nil
}

func parseIPPattern(ipp string) (*net.IPNet, error) {
	ipnet := net.IPNet{}
	ipnet.IP = net.ParseIP(ipp)
	if ipnet.IP != nil {
		if ipnet.IP.To4() != nil {
			ipnet.Mask = net.CIDRMask(32, 32)
		} else {
			ipnet.Mask = net.CIDRMask(128, 128)
		}
		return &ipnet, nil
	} else {
		_, ipnet, err := net.ParseCIDR(ipp)
		if err != nil {
			return nil, err
		}
		return ipnet, nil
	}
}

func validateMatchConditions(mc *MatchConditions) error {
	for _, p := range []*string{mc.Account, mc.Type, mc.Name} {
		if p == nil {
			continue
		}
		err := validatePattern(*p)
		if err != nil {
			return fmt.Errorf("invalid pattern %q: %s", *p, err)
		}
	}
	if mc.IP != nil {
		_, err := parseIPPattern(*mc.IP)
		if err != nil {
			return fmt.Errorf("invalid IP pattern: %s", err)
		}
	}
	return nil
}

func sp(s string) *string {
    return &s
}

// NewACLAuthorizer Creates a new static authorizer with ACL that have been read from the config file
func NewACLAuthorizer(acl ACL) (Authorizer, error) {
    // Read users with push permission from redis ("not-limit-users")
    var notLimitUsers []string
    var client *redis.Client
    err := errors.New("error")
    for err != nil {
        client = redis.NewClient(&redis.Options{
            Addr: "redisalpine:6379",
            Password: "",
            DB: 0,

        })
        pong, err := client.Ping().Result()
        if err !=  nil {
            fmt.Print(pong, err)
            fmt.Print("Trying connect redis")
            time.Sleep(20 * time.Second)
        }
    }
    notLimitUsers, err = client.SMembers("not-limit-users").Result()
    if err !=  nil {
        panic(err)
    }

    var aclNew []ACLEntry
    for _, user := range notLimitUsers {
        act := []string{"*"}
        x := acl[0]
        firstAcl := x
        m := MatchConditions{Account: sp(user)}
        firstAcl.Match = &m
        firstAcl.Actions = &act
        aclNew = append(aclNew, firstAcl)
    }
    aclNew = append(aclNew, acl[0])
    // END. Read users with push permission from redis ("not-limit-users")
	for i, e := range aclNew {
fmt.Printf("%v\n", e)
		err := validateMatchConditions(e.Match)
		if err != nil {
			return nil, fmt.Errorf("entry %d, invalid match conditions: %s", i, err)
		}
	}
	glog.V(1).Infof("Created ACL Authorizer with %d entries", len(aclNew))
	return &aclAuthorizer{acl: aclNew}, nil
}

func (aa *aclAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	for _, e := range aa.acl {
		matched := e.Matches(ai)
		if matched {
			glog.V(2).Infof("%s matched %s (Comment: %s)", ai, e, e.Comment)
			if len(*e.Actions) == 1 && (*e.Actions)[0] == "*" {
				return ai.Actions, nil
			}
			return StringSetIntersection(ai.Actions, *e.Actions), nil
		}
	}
	return nil, NoMatch
}

func (aa *aclAuthorizer) Stop() {
	// Nothing to do.
}

func (aa *aclAuthorizer) Name() string {
	return "static ACL"
}

type aclEntryJSON *ACLEntry

func (e ACLEntry) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func matchString(pp *string, s string, vars []string) bool {
	if pp == nil {
		return true
	}
	p := strings.NewReplacer(vars...).Replace(*pp)

	var matched bool
	var err error
	if len(p) > 2 && p[0] == '/' && p[len(p)-1] == '/' {
		matched, err = regexp.Match(p[1:len(p)-1], []byte(s))
	} else {
		matched, err = path.Match(p, s)
	}
	return err == nil && matched
}

func matchIP(ipp *string, ip net.IP) bool {
	if ipp == nil {
		return true
	}
	if ip == nil {
		return false
	}
	ipnet, err := parseIPPattern(*ipp)
	if err != nil { // Can't happen, it supposed to have been validated
		glog.Fatalf("Invalid IP pattern: %s", *ipp)
	}
	return ipnet.Contains(ip)
}

func (mc *MatchConditions) Matches(ai *AuthRequestInfo) bool {
	vars := []string{
		"${account}", regexp.QuoteMeta(ai.Account),
		"${type}", regexp.QuoteMeta(ai.Type),
		"${name}", regexp.QuoteMeta(ai.Name),
		"${service}", regexp.QuoteMeta(ai.Service),
	}
	return matchString(mc.Account, ai.Account, vars) &&
		matchString(mc.Type, ai.Type, vars) &&
		matchString(mc.Name, ai.Name, vars) &&
		matchIP(mc.IP, ai.IP)
}

func (e *ACLEntry) Matches(ai *AuthRequestInfo) bool {
	return e.Match.Matches(ai)
}
