package cache

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
)

var m sync.Mutex

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

func Write(sess *session.Session, key, value string) error {
	funcName := GetFunctionName()
	logrus.Debugf("%s | writing key %s with length %d to %s", funcName, key, len(value), sess.CachePath)

	m.Lock()
	err := sess.Cache.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, value, nil)
		if err != nil {
			return err
		}

		return err
	})
	m.Unlock()

	return err
}

func Read(sess *session.Session, key string) (val string, cerr error) {
	funcName := GetFunctionName()

	if sess.Cache == nil {
		return val, fmt.Errorf("%s - session cache not provided", funcName)
	}

	err := sess.Cache.View(func(tx *buntdb.Tx) error {
		var err error
		val, err = tx.Get(key)
		if err != nil && err.Error() != "not found" {
			err = fmt.Errorf("%w", err)
			return err
		}

		return nil
	})

	if sess.Cache == nil {
		logrus.Warnf("%s | opening cache %s - unexpected?", funcName, sess.CachePath)

		sess.Cache, err = buntdb.Open(sess.CachePath)
		if err != nil {
			err = fmt.Errorf("%s: %w", funcName, err)
			return
		}
	}

	err = sess.Cache.View(func(tx *buntdb.Tx) error {
		val, err = tx.Get(key)
		if err != nil && err.Error() != "not found" {
			err = fmt.Errorf("%w", err)
			return err
		}

		return nil
	})

	if err != nil && err.Error() == "not found" {
		logrus.Debugf("%s | %s not found in the db", funcName, key)

		err = nil
	}

	return
}
