package cache

import (
	"fmt"
	"sync"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
)

var m sync.Mutex

func Write(sess *session.Session, key, value string) error {
	funcName := helpers.GetFunctionName()
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

func Read(sess *session.Session, key string) (string, error) {
	if sess.Cache == nil {
		return "", fmt.Errorf("%s - session cache not provided", helpers.GetFunctionName())
	}

	var val string
	err := sess.Cache.View(func(tx *buntdb.Tx) error {
		var err error
		val, err = tx.Get(key)
		if err != nil && err != buntdb.ErrNotFound {
			return err
		}
		return nil
	})
	if err == buntdb.ErrNotFound {
		logrus.Debugf("%s | %s not found in the db", helpers.GetFunctionName(), key)
		return "", nil
	}

	return val, err
}
