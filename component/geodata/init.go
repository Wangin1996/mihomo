package geodata

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var (
	initGeoSite bool
	initGeoIP   int
	initASN     bool

	initGeoSiteMutex sync.Mutex
	initGeoIPMutex   sync.Mutex
	initASNMutex     sync.Mutex

	geoIpEnable   atomic.Bool
	geoSiteEnable atomic.Bool
	asnEnable     atomic.Bool

	urlMu      sync.RWMutex
	geoIpUrl   string
	mmdbUrl    string
	geoSiteUrl string
	asnUrl     string
)

func GeoIpUrl() string {
	urlMu.RLock()
	defer urlMu.RUnlock()
	return geoIpUrl
}

func SetGeoIpUrl(url string) {
	urlMu.Lock()
	geoIpUrl = url
	urlMu.Unlock()
}

func MmdbUrl() string {
	urlMu.RLock()
	defer urlMu.RUnlock()
	return mmdbUrl
}

func SetMmdbUrl(url string) {
	urlMu.Lock()
	mmdbUrl = url
	urlMu.Unlock()
}

func GeoSiteUrl() string {
	urlMu.RLock()
	defer urlMu.RUnlock()
	return geoSiteUrl
}

func SetGeoSiteUrl(url string) {
	urlMu.Lock()
	geoSiteUrl = url
	urlMu.Unlock()
}

func ASNUrl() string {
	urlMu.RLock()
	defer urlMu.RUnlock()
	return asnUrl
}

func SetASNUrl(url string) {
	urlMu.Lock()
	asnUrl = url
	urlMu.Unlock()
}

func downloadToPath(url string, path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if err = os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func InitGeoSite() error {
	geoSiteEnable.Store(true)
	initGeoSiteMutex.Lock()
	defer initGeoSiteMutex.Unlock()
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadToPath(GeoSiteUrl(), C.Path.GeoSite()); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
		initGeoSite = false
	}
	if !initGeoSite {
		if err := Verify(C.GeositeName); err != nil {
			log.Warnln("GeoSite.dat invalid, remove and download: %s", err)
			if err := os.Remove(C.Path.GeoSite()); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("can't remove invalid GeoSite.dat: %s", err.Error())
			}
			if err := downloadToPath(GeoSiteUrl(), C.Path.GeoSite()); err != nil {
				return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
			}
			if err := Verify(C.GeositeName); err != nil {
				_ = os.Remove(C.Path.GeoSite())
				return fmt.Errorf("downloaded GeoSite.dat invalid: %s", err.Error())
			}
		}
		initGeoSite = true
	}
	return nil
}

func InitGeoIP() error {
	geoIpEnable.Store(true)
	initGeoIPMutex.Lock()
	defer initGeoIPMutex.Unlock()
	if GeodataMode() {
		if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
			log.Infoln("Can't find GeoIP.dat, start download")
			if err := downloadToPath(GeoIpUrl(), C.Path.GeoIP()); err != nil {
				return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
			}
			log.Infoln("Download GeoIP.dat finish")
			initGeoIP = 0
		}

		if initGeoIP != 1 {
			if err := Verify(C.GeoipName); err != nil {
				log.Warnln("GeoIP.dat invalid, remove and download: %s", err)
				if err := os.Remove(C.Path.GeoIP()); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("can't remove invalid GeoIP.dat: %s", err.Error())
				}
				if err := downloadToPath(GeoIpUrl(), C.Path.GeoIP()); err != nil {
					return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
				}
				if err := Verify(C.GeoipName); err != nil {
					_ = os.Remove(C.Path.GeoIP())
					return fmt.Errorf("downloaded GeoIP.dat invalid: %s", err.Error())
				}
			}
			initGeoIP = 1
		}
		return nil
	}

	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadToPath(MmdbUrl(), C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
		initGeoIP = 0
	}

	if initGeoIP != 2 {
		if !mmdb.Verify(C.Path.MMDB()) {
			log.Warnln("MMDB invalid, remove and download")
			if err := os.Remove(C.Path.MMDB()); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("can't remove invalid MMDB: %s", err.Error())
			}
			if err := downloadToPath(MmdbUrl(), C.Path.MMDB()); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
			if !mmdb.Verify(C.Path.MMDB()) {
				_ = os.Remove(C.Path.MMDB())
				return fmt.Errorf("downloaded MMDB invalid")
			}
		}
		initGeoIP = 2
	}
	return nil
}

func InitASN() error {
	asnEnable.Store(true)
	initASNMutex.Lock()
	defer initASNMutex.Unlock()
	if _, err := os.Stat(C.Path.ASN()); os.IsNotExist(err) {
		log.Infoln("Can't find ASN.mmdb, start download")
		if err := downloadToPath(ASNUrl(), C.Path.ASN()); err != nil {
			return fmt.Errorf("can't download ASN.mmdb: %s", err.Error())
		}
		log.Infoln("Download ASN.mmdb finish")
		initASN = false
	}
	if !initASN {
		if !mmdb.Verify(C.Path.ASN()) {
			log.Warnln("ASN invalid, remove and download")
			if err := os.Remove(C.Path.ASN()); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("can't remove invalid ASN: %s", err.Error())
			}
			if err := downloadToPath(ASNUrl(), C.Path.ASN()); err != nil {
				return fmt.Errorf("can't download ASN: %s", err.Error())
			}
			if !mmdb.Verify(C.Path.ASN()) {
				_ = os.Remove(C.Path.ASN())
				return fmt.Errorf("downloaded ASN.mmdb invalid")
			}
		}
		initASN = true
	}
	return nil
}

func GeoIpEnable() bool {
	return geoIpEnable.Load()
}

func GeoSiteEnable() bool {
	return geoSiteEnable.Load()
}

func ASNEnable() bool {
	return asnEnable.Load()
}
