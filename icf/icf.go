package icf

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"os/exec"
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
	driverName         = "icf"
	defaultSSHUser     = "centos"
	defaultSSHPassword = "centos"
)

const (
	keypairNotFoundCode = "InvalidKeyPair.NotFound"
)

var (
	dockerPort                = 2376
	swarmPort                 = 3376
	errorMissingCredentials   = errors.New("icf driver requires ICFB credentials (--icf-user and --icf-password)")
	errorMissingIcfServer     = errors.New("icf driver requires ICFB IP address (--icf-server)")
	errorMissingServerCert    = errors.New("icf driver requires ICFB Server Certificate (--icf-server-cert)")
	errorMissingVdc           = errors.New("icf driver requires VDC ID (--icf-vdc)")
	errorMissingCatalog       = errors.New("icf driver requires Catalog ID (--icf-catalog)")
	errorMissingNetwork       = errors.New("icf driver requires Network ID (--icf-network)")
	errorMissingVMCredentials = errors.New("icf driver requires VM Credentials (--icf-ssh-username and --icf-ssh-password)")
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
	SSHPassword       string
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
		mcnflag.BoolFlag{
			Name:   "icf-provider-access",
			Usage:  "ICF Provider Access",
			EnvVar: "ICF_PROVIDER_ACCESS",
		},
		mcnflag.StringFlag{
			Name:   "icf-ssh-username",
			Usage:  "Set the name of the ssh user",
			EnvVar: "ICF_SSH_USER",
		},
		mcnflag.StringFlag{
			Name:   "icf-ssh-password",
			Usage:  "Set the password of the ssh user",
			EnvVar: "ICF_SSH_PASSWORD",
		},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	id := generateId()
	driver := &Driver{
		Id: id,
		BaseDriver: &drivers.BaseDriver{
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

	log.Debugf("[DEBUG] Server Cert = %s", d.ServerCert)
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
	d.SSHUser = flags.String("icf-ssh-username")
	d.SSHPassword = flags.String("icf-ssh-password")

	if d.Username == "" || d.Password == "" {
		return errorMissingCredentials
	}

	if d.Server == "" {
		return errorMissingIcfServer
	}

	if d.ServerCert == "" {
		return errorMissingServerCert
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

	if d.SSHUser == "" || d.SSHPassword == "" {
		return errorMissingVMCredentials
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

	err = d.createKeyPair()
	/*
		if err != nil {
			d.Remove()
		}
	*/
	return nil /* docker-machine doesn't learn IP address on failure preventing rm */
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

func (d *Driver) GetSSHPassword() string {
	if d.SSHPassword == "" {
		d.SSHPassword = defaultSSHPassword
	}

	return d.SSHPassword
}

func (d *Driver) Start() error {
	log.Infof("[INFO] Start entered")
	//err := d.createKeyPair()
	//return err
	return fmt.Errorf("Unsupported operation")
}

func (d *Driver) Stop() error {
	log.Infof("[INFO] Stop entered")
	return fmt.Errorf("Unsupported operation")
}

func (d *Driver) Restart() error {
	log.Infof("[INFO] Restart entered")
	//err := d.createKeyPair()
	//return err
	return fmt.Errorf("Unsupported operation")
}

func (d *Driver) Kill() error {
	return fmt.Errorf("Unsupported operation")
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
		log.Debugf("[DEBUG] instanceIsRunning : Running")
		return true
	}
	log.Debugf("[DEBUG] instanceIsRunning : Not Running")
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

func (d *Driver) getSSHCommandFromDriver(command string) (*exec.Cmd, error) {
	address, err := d.GetSSHHostname()
	if err != nil {
		return nil, err
	}

	port, err := d.GetSSHPort()
	if err != nil {
		return nil, err
	}

	sshBinaryPath, err := exec.LookPath("ssh")
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	sshpassBinaryPath, err := exec.LookPath("sshpass")
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	log.Infof("[DEBUG] Connecting to %s, as %s", address, d.GetSSHUsername())
	cmd := exec.Command(sshpassBinaryPath, "-p", d.GetSSHPassword(), sshBinaryPath,
		"-o", "StrictHostKeyChecking=no", "-l", d.GetSSHUsername(), "-p", fmt.Sprintf("%d", port),
		address, command)
	return cmd, err

}

func (d *Driver) runSSHCommandFromDriver(command string) (string, error) {
	cmd, err := d.getSSHCommandFromDriver(command)
	if err != nil {
		log.Infof("[DEBUG] Error in d.getSSHClientFromDriver (%v)", err)
		return "", err
	}

	log.Infof("[DEBUG] Executing via SSH,  Command:%v", cmd)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(`Something went wrong running an SSH command!
command : %s
err     : %v
output  : %s
`, command, err, string(output))
	}

	return string(output), nil
}

func (d *Driver) sshAvailableFunc() func() bool {
	return func() bool {
		if _, err := d.runSSHCommandFromDriver("exit 0"); err != nil {
			log.Infof("[ERROR] Error executing ssh command 'exit 0' : %s", err)
			return false
		}
		return true
	}
}

func (d *Driver) waitForSSH() error {
	// Try to dial SSH for 30 seconds before timing out.
	log.Info("[INFO] Checking if ssh is available")
	if err := mcnutils.WaitFor(d.sshAvailableFunc()); err != nil {
		return fmt.Errorf("Too many retries waiting for SSH to be available.  Last error: %s", err)
	}
	return nil
}

func (d *Driver) disableFirewall() error {

	if err := d.waitForSSH(); err != nil {
		return err
	}

	log.Debugf("[DEBUG] Disabling Firewall")

	cmd := "/usr/bin/systemctl stop firewalld; /usr/bin/systemctl disable firewalld"
	log.Debugf("[DEBUG] Remote Command is = %s", cmd)

	_, err := d.runSSHCommandFromDriver(cmd)
	if err != nil {
		log.Error(err.Error())
	}
	return err
}

func (d *Driver) disableKernelUpdate() error {

	if err := d.waitForSSH(); err != nil {
		return err
	}

	log.Debugf("[DEBUG] Disabling kernel updates")

	cmd := "/usr/bin/echo " + "exclude=centos-release* redhat-release* kernel*" + " >> /etc/yum.conf"
	log.Debugf("[DEBUG] Remote Command is = %s", cmd)

	_, err := d.runSSHCommandFromDriver(cmd)
	if err != nil {
		log.Error(err.Error())
	}
	return err
}

func (d *Driver) setKey(key string) error {

	if err := d.waitForSSH(); err != nil {
		return err
	}

	log.Debugf("[DEBUG] Copying key : Key (%s)", key)

	homedir := "/home/"
	if strings.Compare(d.SSHUser, "root") == 0 {
		homedir = "/"
	}

	cmd := "/usr/bin/echo " + strings.TrimSpace(key) + " >> " + homedir + d.SSHUser + "/.ssh/authorized_keys"
	log.Debugf("[DEBUG] Remote Command is = %s", cmd)

	_, err := d.runSSHCommandFromDriver(cmd)
	if err != nil {
		log.Error(err.Error())
	}
	return err
}

func (d *Driver) createKeyPair() (err error) {
	type authKeyInfo struct {
		User string `json:"user"`
		Key  string `json:"key"`
	}
	log.Debugf("[DEBUG] createKey : Entered")

	keyPath := ""

	if d.SSHPrivateKeyPath == "" {
		log.Infof("[INFO] Creating New SSH Key in %s", d.GetSSHKeyPath())
		if err = ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
			err = fmt.Errorf("[ERROR] Error generating SSH Key : %v", err)
			log.Error(err.Error())
			return
		}
		log.Infof("[INFO] Generated Key ")
		keyPath = d.GetSSHKeyPath()
	} else {
		log.Infof("Using ExistingKeyPair from %s", d.SSHPrivateKeyPath)
		if err = mcnutils.CopyFile(d.SSHPrivateKeyPath, d.GetSSHKeyPath()); err != nil {
			err = fmt.Errorf("[ERROR] Error copying private Key in",
				d.SSHPrivateKeyPath)
			log.Error(err.Error())
			return
		}
		if err = mcnutils.CopyFile(d.SSHPrivateKeyPath+".pub", d.GetSSHKeyPath()+".pub"); err != nil {
			err = fmt.Errorf("[ERROR] createKey : Error copying public Key in",
				d.SSHPrivateKeyPath)
			log.Error(err.Error())
			return
		}
		keyPath = d.SSHPrivateKeyPath
	}

	var publicKey []byte
	publicKey, err = ioutil.ReadFile(keyPath + ".pub")
	if err != nil {
		err = fmt.Errorf("[ERROR] Unable to read Key file: %s", keyPath)
		log.Error(err.Error())
		return
	}

	log.Infof("[INFO] Setting key ")
	if err = d.setKey(string(publicKey)); err != nil {
		err = fmt.Errorf("[ERROR] Error setting key: %v", err)
		log.Error(err.Error())
		return
	}
	log.Debugf("[DEBUG] createKey : Success")

	log.Debugf("[INFO] Disabling Kernel Update")
	if err = d.disableKernelUpdate(); err != nil {
		err = fmt.Errorf("[ERROR] Error disabling Kernel updates: %v", err)
		log.Error(err.Error())
		return
	}
	log.Debugf("[DEBUG] Disable Kernel Update : Success")

	log.Debugf("[INFO] Disabling Firewall")
	if err = d.disableFirewall(); err != nil {
		err = fmt.Errorf("[ERROR] Error disabling Firewall: %v", err)
		log.Error(err.Error())
		return
	}
	log.Debugf("[DEBUG] Disable Firewall : Success")

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
