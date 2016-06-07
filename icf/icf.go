package icf

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CiscoInterCloudFabric/icf-sdk-go/icf"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

const (
	driverName     = "icf"
	defaultSSHUser = "centos"
)

const (
	keypairNotFoundCode = "InvalidKeyPair.NotFound"
)

var (
	dockerPort              = 2376
	swarmPort               = 3376
	errorMissingCredentials = errors.New("icf driver requires username & password")
	errorMissingIcfServer   = errors.New("icf driver requires IP address")
	errorMissingVdc         = errors.New("icf driver requires VDC ID")
	errorMissingCatalog     = errors.New("icf driver requires Catalog ID")
	errorMissingNetwork     = errors.New("icf driver requires Network ID")
	errorMissingSshUser     = errors.New("icf driver requires ssh username")
)

type Driver struct {
	*drivers.BaseDriver
	Id                string
	Username          string
	Password          string
	Server            string
	ServerCert        string
	Vdc               string
	Catalog           string
	Network           string
	ProviderAccess    bool
	InstanceId        string
	KeyName           string
	SSHPrivateKeyPath string
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "icf-username",
			Usage:  "ICF username",
			EnvVar: "ICF_USERNAME",
		},
		mcnflag.StringFlag{
			Name:   "icf-password",
			Usage:  "ICF password",
			EnvVar: "ICF_PASSWORD",
		},
		mcnflag.StringFlag{
			Name:   "icf-server",
			Usage:  "ICFB IP address",
			EnvVar: "ICF_SERVER",
		},
		mcnflag.StringFlag{
			Name:   "icf-server-cert",
			Usage:  "ICF Server Certificate",
			Value:  "",
			EnvVar: "ICF_SERVER_CERT",
		},
		mcnflag.StringFlag{
			Name:   "icf-vdc",
			Usage:  "ICF VDC",
			EnvVar: "ICF_VDC",
		},
		mcnflag.StringFlag{
			Name:   "icf-catalog",
			Usage:  "ICF Catalog",
			EnvVar: "ICF_CATALOG",
		},
		mcnflag.StringFlag{
			Name:   "icf-network",
			Usage:  "ICF Network",
			EnvVar: "ICF_NETWORK",
		},
		mcnflag.StringFlag{
			Name:   "icf-provider-access",
			Usage:  "ICF Provider Access",
			EnvVar: "ICF_PROVIDER_ACCESS",
		},
		mcnflag.StringFlag{
			Name:   "icf-ssh-user",
			Usage:  "Set the name of the ssh user",
			Value:  defaultSSHUser,
			EnvVar: "ICF_SSH_USER",
		},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	id := generateId()
	driver := &Driver{
		Id: id,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}

	//log.StartLogger("docker-machine-icf", true)

	return driver
}

func (d *Driver) config() (cfg *icf.Config) {
	cfg = &icf.Config{
		Credentials: icf.Credentials{
			Username: d.Username,
			Password: d.Password,
		},
		EndPoint:   d.Server,
		Protocol:   "https",
		Root:       "icfb/v1",
		ServerCert: d.ServerCert,
	}

	//log.Debugf("[INFO] Server Cert = %s", d.ServerCert)
	return
}

func (d *Driver) instanceConfig() (cfg *icf.Instance) {
	cfg = &icf.Instance{
		Name:           d.BaseDriver.MachineName,
		Vdc:            d.Vdc,
		Catalog:        d.Catalog,
		ProviderAccess: d.ProviderAccess,
		Nics: []icf.InstanceNicInfo{
			{
				Index:   1,
				Dhcp:    false,
				Network: d.Network,
			},
		},
	}

	return
}

func (d *Driver) getClient() *icf.Client {
	return icf.NewClient(d.config())
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {

	d.Username = flags.String("icf-username")
	d.Password = flags.String("icf-password")
	d.Server = flags.String("icf-server")
	d.ServerCert = flags.String("icf-server-cert")
	d.Vdc = flags.String("icf-vdc")
	d.Catalog = flags.String("icf-catalog")
	d.Network = flags.String("icf-network")
	d.ProviderAccess = flags.Bool("icf-provider-access")
	d.SSHUser = flags.String("icf-ssh-user")

	if d.Username == "" || d.Password == "" {
		return errorMissingCredentials
	}

	if d.Server == "" {
		return errorMissingIcfServer
	}

	if d.Vdc == "" {
		return errorMissingVdc
	}

	if d.Catalog == "" {
		return errorMissingCatalog
	}

	if d.Network == "" {
		return errorMissingNetwork
	}

	if d.SSHUser == "" {
		return errorMissingSshUser
	}

	if d.isSwarmMaster() {
		u, err := url.Parse(d.SwarmHost)
		if err != nil {
			return fmt.Errorf("error parsing swarm host: %s", err)
		}

		parts := strings.Split(u.Host, ":")
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}

		swarmPort = port
	}

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) PreCreateCheck() error {
	return nil
}

func (d *Driver) Create() (err error) {
	log.Infof("[INFO] Creating ICF instance...")

	c := d.getClient()

	instance := d.instanceConfig()

	instance, err = c.CreateInstance(instance)
	if err != nil {
		log.Error("[ERROR] Creating Instance %v", err)
		return
	}

	log.Infof("[INFO] Instance (%s) create initiated", instance.Oid)

	// Store the resulting ID so we can look this up later
	d.InstanceId = instance.Oid

	err = d.waitForInstance()
	log.Infof("[INFO] Instance (%s) is ready", instance.Oid)

	d.createKeyPair()
	return
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, strconv.Itoa(dockerPort))), nil
}

func (d *Driver) GetIP() (string, error) {
	inst, err := d.getInstance()
	if err != nil {
		return "", err
	}

	if inst.Nics[0].Ip == "" {
		return "", fmt.Errorf("No IP for instance %v", inst.Oid)
	}
	return inst.Nics[0].Ip, nil
}

func (d *Driver) GetState() (state.State, error) {
	status := ""
	inst, err := d.getInstance()
	if err != nil {
		errs := fmt.Sprintf("%v", err)
		if strings.Contains(errs, "404") || strings.Contains(errs, "400") {
			status = icf.StatusDeleted
			err = nil
		} else {
			log.Error("[ERROR] GetState : Error = ", err)
		}
	} else {
		status = inst.Status
	}
	switch status {
	case icf.StatusCreateInProgress:
		return state.Starting, nil
	case icf.StatusSuccess:
		return state.Running, nil
	case icf.StatusDeleteInProgress:
		return state.Stopping, nil
	case icf.StatusDeleted:
		return state.Error, nil
	default:
		log.Error("[ERROR] GetState : unrecognized instance state: %v", inst.Status)
		return state.Error, nil
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = defaultSSHUser
	}

	return d.SSHUser
}

func (d *Driver) Start() error {
	return d.waitForInstance()
}

func (d *Driver) Stop() error {
	return d.waitForInstance()
}

func (d *Driver) Restart() error {
	return d.waitForInstance()
}

func (d *Driver) Kill() error {
	return d.waitForInstance()
}

func (d *Driver) Remove() error {
	if err := d.terminate(); err != nil {
		return fmt.Errorf("unable to terminate instance: %s", err)
	}

	return nil
}

func (d *Driver) getInstance() (inst *icf.Instance, err error) {
	inst, err = d.getClient().GetInstance(d.InstanceId)
	if err != nil {
		inst = nil
		return
	}
	return
}

func (d *Driver) instanceIsRunning() bool {
	st, err := d.GetState()
	if err != nil {
		log.Error("[ERROR] instanceIsRunning : Error = %v", err)
	}
	if st == state.Running {
		log.Infof("[INFO] instanceIsRunning : Running")
		return true
	}
	//log.Debugf("[Debug] instanceIsRunning : Not Running")
	return false
}

func (d *Driver) waitForInstance() error {
	if err := mcnutils.WaitForSpecific(d.instanceIsRunning, 60, 10*time.Second); err != nil {
		return err
	}

	return nil
}

const (
	defaultRequestTimeout = 10 * time.Second
)

func post(hostname string, path string, data []byte) (err error) {
	var req *http.Request
	var resp *http.Response

	hclient := &http.Client{Timeout: defaultRequestTimeout}
	url := "http://" + hostname + ":8787" + path
	//log.Debugf("[Debug] Posting url(%s) data(%s)", url, string(data))
	if req, err = http.NewRequest("POST", url, bytes.NewBuffer(data)); err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	if resp, err = hclient.Do(req); err != nil {
		log.Error("[ERROR] post : Error = %v", err)
		return
	}
	sc := resp.StatusCode
	status := resp.Status
	if data, err = ioutil.ReadAll(resp.Body); err == nil {
		/* log.Debugf("[Debug] Response sc(%d) status(%s) msg (%s)",
		sc, status, string(data)) */
	}
	if sc >= 300 || sc < 100 {
		err = fmt.Errorf("%s", status)
		return
	}

	return
}

func (d *Driver) createKeyPair() error {
	type authKeyInfo struct {
		User string `json:"user"`
		Key  string `json:"key"`
	}
	log.Debugf("[Debug] createKey : Entered")

	keyPath := ""

	if d.SSHPrivateKeyPath == "" {
		log.Infof("[INFO] createKey : Creating New SSH Key in ", d.GetSSHKeyPath())
		if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
			return err
		}
		log.Infof("[INFO] createKey : Generated Key : Path %s", d.GetSSHKeyPath())
		keyPath = d.GetSSHKeyPath()
	} else {
		log.Infof("createKey : Using ExistingKeyPair: %s", d.SSHPrivateKeyPath)
		if err := mcnutils.CopyFile(d.SSHPrivateKeyPath, d.GetSSHKeyPath()); err != nil {
			log.Error("[ERROR] createKey : Error copying private Key in", d.SSHPrivateKeyPath)
			return err
		}
		if err := mcnutils.CopyFile(d.SSHPrivateKeyPath+".pub", d.GetSSHKeyPath()+".pub"); err != nil {
			log.Error("[ERROR] createKey : Error copying public Key in", d.SSHPrivateKeyPath)
			return err
		}
		keyPath = d.SSHPrivateKeyPath
	}

	publicKey, err := ioutil.ReadFile(keyPath + ".pub")
	if err != nil {
		log.Error("[ERROR] createKey : Unable to read Key file: %s", keyPath)
		return err
	}

	authKey := &authKeyInfo{
		User: d.GetSSHUsername(),
		Key:  string(publicKey),
	}

	var data []byte
	var hostname string

	data, err = json.Marshal(&authKey)
	if err != nil {
		log.Error("[ERROR] createKey : Unable to Marshal: %v", authKey)
		return err
	}
	log.Debugf("[Debug] createKey : Setting Key (%s)", string(data))

	time.Sleep(time.Second * 20)
	hostname, err = d.GetSSHHostname()
	if err = post(hostname, "/api/authkey", data); err != nil {
		log.Error("[ERROR] createKey : Error setting key: %v", err)
		return err
	}
	log.Debugf("[Debug] createKey : Success")
	return nil
}

func (d *Driver) terminate() error {
	if d.InstanceId == "" {
		return fmt.Errorf("unknown instance")
	}

	log.Infof("[INFO] terminating ICF instance: %s", d.InstanceId)
	err := d.getClient().DeleteInstance(d.InstanceId)
	if err != nil {
		log.Error("[ERROR] Error in terminating instance (%s) : %v", d.InstanceId, err)
		return fmt.Errorf("unable to terminate instance: %s", err)
	}
	log.Infof("[INFO] terminated instance: %s", d.InstanceId)
	return nil
}

func (d *Driver) isSwarmMaster() bool {
	return d.SwarmMaster
}

func generateId() string {
	rb := make([]byte, 10)
	_, err := rand.Read(rb)
	if err != nil {
		log.Error("[ERROR] Unable to generate id: %s", err)
	}

	h := md5.New()
	io.WriteString(h, string(rb))
	return fmt.Sprintf("%x", h.Sum(nil))
}
