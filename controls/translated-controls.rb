control "xccdf_org.cisecurity.benchmarks_rule_1.1.1_Create_Separate_Partition_for_tmp" do
  title "Create Separate Partition for /tmp"
  desc  "
    The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.
    
    Rationale: Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2_Set_nodev_option_for_tmp_Partition" do
  title "Set nodev option for /tmp Partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp.
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3_Set_nosuid_option_for_tmp_Partition" do
  title "Set nosuid option for /tmp Partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain set userid files.
    
    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create set userid files in /tmp.
    
    # mount -o remount,nosuid /tmp
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4_Set_noexec_option_for_tmp_Partition" do
  title "Set noexec option for /tmp Partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp.
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5_Create_Separate_Partition_for_var" do
  title "Create Separate Partition for /var"
  desc  "
    The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.
    
    Rationale: Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition.
  "
  impact 1.0
  describe mount("/var") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6_Bind_Mount_the_vartmp_directory_to_tmp" do
  title "Bind Mount the /var/tmp directory to /tmp"
  desc  "
    The /var/tmp directory is normally a standalone directory in the /var file system. Binding /var/tmp to /tmp establishes an unbreakable link to /tmp that cannot be removed (even by the root user). It also allows /var/tmp to inherit the same mount options that /tmp owns, allowing /var/tmp to be protected in the same /tmp is protected. It will also prevent /var from filling up with temporary files as the contents of /var/tmp will actually reside in the file system containing /tmp.
    
    Rationale: All programs that use /var/tmp and /tmp to read/write temporary files will always be written to the /tmp file system, preventing a user from running the /var file system out of space or trying to perform operations that have been blocked in the /tmp filesystem.
  "
  impact 1.0
  describe file("/etc/fstab") do
    its("content") { should match(/$\s*\/tmp\s+\/var\/tmp\s+none\s+bind\s+0\s+0\s*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.7_Create_Separate_Partition_for_varlog" do
  title "Create Separate Partition for /var/log"
  desc  "
    The /var/log directory is used by system services to store log data .
    
    Rationale: There are two important reasons to ensure that system logs are stored on a separate partition: protection against resource exhaustion (since logs can grow quite large) and protection of audit data.
  "
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.8_Create_Separate_Partition_for_varlogaudit" do
  title "Create Separate Partition for /var/log/audit"
  desc  "
    The auditing daemon, auditd, stores log data in the /var/log/audit directory.
    
    Rationale: There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. The audit daemon calculates how much free space is left and performs actions based on the results. If other processes (such as syslog) consume space in the same partition as auditd, it may not perform as desired.
  "
  impact 1.0
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.9_Create_Separate_Partition_for_home" do
  title "Create Separate Partition for /home"
  desc  "
    The /home directory is used to support disk storage needs of local users.
    
    Rationale: If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home.
  "
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.10_Add_nodev_Option_to_home" do
  title "Add nodev Option to /home"
  desc  "
    When set on a file system, this option prevents character and block special devices from being defined, or if they exist, from being used as character and block special devices.
    
    Rationale: Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices.
    
    **Note:** The actions in the item refer to the /home partition. If you have created other user partitions, it is recommended that the Remediation and Audit steps be applied to these partitions as well.
  "
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
  describe mount("/home") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.11_Add_nodev_Option_to_Removable_Media_Partitions" do
  title "Add nodev Option to Removable Media Partitions"
  desc  "
    Set nodev on removable media to prevent character and block special devices that are present on the removable be treated as these device files.
    
    Rationale: Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.12_Add_noexec_Option_to_Removable_Media_Partitions" do
  title "Add noexec Option to Removable Media Partitions"
  desc  "
    Set noexec on removable media to prevent programs from executing from the removable media.
    
    Rationale: Setting this option on a file system prevents users from executing programs from the removable. This deters users from being to introduce potentially malicious software on the system.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.13_Add_nosuid_Option_to_Removable_Media_Partitions" do
  title "Add nosuid Option to Removable Media Partitions"
  desc  "
    Set nosuid on removable media to prevent setuid and setgid executable files that are on that media from being executed as setuid and setgid.
    
    Rationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.14_Add_nodev_Option_to_devshm_Partition" do
  title "Add nodev Option to /dev/shm Partition"
  desc  "
    The nodev mount option specifies that the /dev/shm (temporary filesystem stored in memory) cannot contain block or character special devices.
    
    Rationale: Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions.
  "
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.15_Add_nosuid_Option_to_devshm_Partition" do
  title "Add nosuid Option to /dev/shm Partition"
  desc  "
    The nosuid mount option specifies that the /dev/shm (temporary filesystem stored in memory) will not execute setuid and setgid on executable programs as such, but rather execute them with the uid and gid of the user executing the program.
    
    Rationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.16_Add_noexec_Option_to_devshm_Partition" do
  title "Add noexec Option to /dev/shm Partition"
  desc  "
    Set noexec on the shared memory partition to prevent programs from executing from there.
    
    Rationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.
  "
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.17_Set_Sticky_Bit_on_All_World-Writable_Directories" do
  title "Set Sticky Bit on All World-Writable Directories"
  desc  "
    Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.
    
    Rationale: This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user.
  "
  impact 1.0
  describe command("find / -type d -perm -00002 \\! -perm -01000 -xdev") do
    its("stdout") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.1_Verify_CentOS_GPG_Key_is_Installed" do
  title "Verify CentOS GPG Key is Installed"
  desc  "
    CentOS cryptographically signs updates with a GPG key to verify that they are valid.
    
    Rationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system.
  "
  impact 1.0
  describe package("gpg-pubkey") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.2_Verify_that_gpgcheck_is_Globally_Activated" do
  title "Verify that gpgcheck is Globally Activated"
  desc  "
    The gpgcheck option, found in the main section of the /etc/yum.conf file determines if an RPM package's signature is always checked prior to its installation.
    
    Rationale: It is important to ensure that an RPM's package signature is always checked prior to installation to ensure that the software is obtained from a trusted source.
  "
  impact 1.0
  describe file("/etc/yum.conf") do
    its("content") { should match(/^\s*gpgcheck=1\s*(#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.3_Obtain_Software_Package_Updates_with_yum" do
  title "Obtain Software Package Updates with yum"
  desc  "
    The yum update utility performs software updates, including dependency analysis, based on repository metadata and can be run manually from the command line, invoked from one of the provided front-end tools, or configured to run automatically at specified intervals.
    
    Rationale: The yum update utility is the preferred method to update software since it checks for dependencies and ensures that the software is installed correctly. Refer to your local patch management procedures for the method used to perform yum updates.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.4_Verify_Package_Integrity_Using_RPM" do
  title "Verify Package Integrity Using RPM"
  desc  "
    RPM has the capability of verifying installed packages by comparing the installed files against the file information stored in the package.
    
    Rationale: Verifying packages gives a system administrator the ability to detect if package files were changed, which could indicate that a valid binary was overwritten with a trojaned binary.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.1_Set_UserGroup_Owner_on_bootgrub2grub.cfg" do
  title "Set User/Group Owner on /boot/grub2/grub.cfg"
  desc  "
    Set the owner and group of /boot/grub2/grub.cfgto the root user.
    
    Rationale: Setting the owner and group to root prevents non-root users from changing the file.
  "
  impact 1.0
  describe file("/boot/grub2/grub.cfg") do
    it { should exist }
  end
  describe file("/boot/grub2/grub.cfg") do
    its("gid") { should cmp 0 }
  end
  describe file("/boot/grub2/grub.cfg") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.2_Set_Permissions_on_bootgrub2grub.cfg" do
  title "Set Permissions on /boot/grub2/grub.cfg"
  desc  "
    Set permission on the /boot/grub2/grub.cfg file to read and write for root only.
    
    Rationale: Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
  "
  impact 1.0
  describe file("/boot/grub2/grub.cfg") do
    it { should exist }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_executable.by "group" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_readable.by "group" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_writable.by "group" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_executable.by "other" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_readable.by "other" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_writable.by "other" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.3_Set_Boot_Loader_Password" do
  title "Set Boot Loader Password"
  desc  "
    Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters
    
    Rationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time).
  "
  impact 1.0
  describe file("/boot/grub2/grub.cfg") do
    its("content") { should match(/^set superusers=".*"\s*(?:#.*)?$/) }
  end
  describe file("/boot/grub2/grub.cfg") do
    its("content") { should match(/^password/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1_Restrict_Core_Dumps" do
  title "Restrict Core Dumps"
  desc  "
    A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.
    
    Rationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core.
  "
  impact 1.0
  describe file("/etc/security/limits.conf") do
    its("content") { should match(/^\s*\*\shard\score\s0(\s+#.*)?$/) }
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.2_Enable_Randomized_Virtual_Memory_Region_Placement" do
  title "Enable Randomized Virtual Memory Region Placement"
  desc  "
    Set the system flag to force randomized virtual memory region placement.
    
    Rationale: Randomly placing virtual memory regions will make it difficult for to write memory page exploits as the memory placement will be consistently shifting.
  "
  impact 1.0
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should eq 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7_Use_the_Latest_OS_Release" do
  title "Use the Latest OS Release"
  desc  "
    Periodically, CentOS releases updates to the CentOS operating system to support new hardware platforms, deliver new functionality as well as the bundle together a set of patches that can be tested as a unit.
    
    Rationale: Newer updates may contain security enhancements that would not be available through the standard patching process. As a result, it is recommended that the latest update of the CentOS software be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.1_Remove_telnet-server" do
  title "Remove telnet-server"
  desc  "
    The telnet-server package contains the telnetd daemon, which accepts connections from users from other systems via the telnet protocol.
    
    Rationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions.
  "
  impact 1.0
  describe package("telnet-server") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.2_Remove_telnet_Clients" do
  title "Remove telnet Clients"
  desc  "
    The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.
    
    Rationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an authorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions.
  "
  impact 1.0
  describe package("telnet") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.3_Remove_rsh-server" do
  title "Remove rsh-server"
  desc  "
    The Berkeley rsh-server (rsh, rlogin, rcp) package contains legacy services that exchange credentials in clear-text.
    
    Rationale: These legacy service contain numerous security exposures and have been replaced with the more secure SSH package.
  "
  impact 1.0
  describe package("rsh-server") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.4_Remove_rsh" do
  title "Remove rsh"
  desc  "
    The rsh package contains the client commands for the rsh services.
    
    Rationale: These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh, rcp and rlogin.
  "
  impact 1.0
  describe package("rsh") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.5_Remove_NIS_Client" do
  title "Remove NIS Client"
  desc  "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.
    
    Rationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  impact 1.0
  describe package("ypbind") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.6_Remove_NIS_Server" do
  title "Remove NIS Server"
  desc  "
    The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.
    
    Rationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used
  "
  impact 1.0
  describe package("ypserv") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.7_Remove_tftp" do
  title "Remove tftp"
  desc  "
    Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot files between machines. TFTP does not support authentication and can be easily hacked. The package tftp is a client program that allows for connections to a tftp server.
    
    Rationale: It is recommended that TFTP be removed, unless there is a specific need for TFTP (such as a boot server). In that case, use extreme caution when configuring the services.
  "
  impact 1.0
  describe package("tftp") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.8_Remove_tftp-server" do
  title "Remove tftp-server"
  desc  "
    Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot machines from a boot server. The package tftp-server is the server package used to define and support a TFTP server.
    
    Rationale: TFTP does not support authentication nor does it ensure the confidentiality of integrity of data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In that case, extreme caution must be used when configuring the services.
  "
  impact 1.0
  describe package("tftp-server") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.9_Remove_talk" do
  title "Remove talk"
  desc  "
    The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initialization of talk sessions) is installed by default.
    
    Rationale: The software presents a security risk as it uses unencrypted protocols for communication.
  "
  impact 1.0
  describe package("talk") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.10_Remove_talk-server" do
  title "Remove talk-server"
  desc  "
    The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initiate of talk sessions) is installed by default.
    
    Rationale: The software presents a security risk as it uses unencrypted protocols for communication.
  "
  impact 1.0
  describe package("talk-server") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.12_Disable_chargen-dgram" do
  title "Disable chargen-dgram"
  desc  "
    chargen-dgram is a network service that responds with 0 to 512 ASCII characters for each datagram it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.
    
    Rationale: Disabling this service will reduce the remote attack surface of the system.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("chargen").protocols("udp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.13_Disable_chargen-stream" do
  title "Disable chargen-stream"
  desc  "
    chargen-stream is a network service that responds with 0 to 512 ASCII characters for each connection it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.
    
    Rationale: Disabling this service will reduce the remote attack surface of the system.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("chargen").protocols("tcp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.14_Disable_daytime-dgram" do
  title "Disable daytime-dgram"
  desc  "
    daytime-dgram is a network service that responds with the server's current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.
    
    Rationale: Disabling this service will reduce the remote attack surface of the system.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("daytime").protocols("udp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.15_Disable_daytime-stream" do
  title "Disable daytime-stream"
  desc  "
    daytime-stream is a network service that responds with the server's current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.
    
    Rationale: Disabling this service will reduce the remote attack surface of the system.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("daytime").protocols("tcp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.16_Disable_echo-dgram" do
  title "Disable echo-dgram"
  desc  "
    echo-dgram is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.
    
    Rationale: Disabling this service will reduce the remote attack surface of the system.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("echo").protocols("udp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.17_Disable_echo-stream" do
  title "Disable echo-stream"
  desc  "
    echo-stream is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.
    
    Rationale: Disabling this service will reduce the remote attack surface of the system.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("echo").protocols("tcp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.18_Disable_tcpmux-server" do
  title "Disable tcpmux-server"
  desc  "
    tcpmux-server is a network service that allows a client to access other network services running on the server. It is recommended that this service be disabled.
    
    Rationale: tcpmux-server can be abused to circumvent the server's host based firewall. Additionally, tcpmux-server can be leveraged by an attacker to effectively port scan the server.
  "
  impact 1.0
  describe.one do
    describe xinetd_conf.services("tcpmux").protocols("tcp") do
      it { should be_disabled }
    end
    describe package("xinetd") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1_Set_Daemon_umask" do
  title "Set Daemon umask"
  desc  "
    Set the default umask for all processes started at boot time. The settings in umask selectively turn off default permission when a file is created by a daemon process.
    
    Rationale: Setting the umask to 027 will make sure that files created by daemons will not be readable, writable or executable by any other than the group and owner of the daemon process and will not be writable by the group of the daemon process. The daemon process can manually override these settings if these files need additional permission.
  "
  impact 1.0
  describe file("/etc/sysconfig/init") do
    its("content") { should match(/^\s*umask\s+027\s*(?:#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2_Remove_the_X_Window_System" do
  title "Remove the X Window System"
  desc  "
    The X Window system provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Window system is typically used on desktops where users login, but not on servers where users typically do not login.
    
    Rationale: Unless your organization specifically requires graphical login access via the X Window System, remove the server to reduce the potential attack surface.
  "
  impact 1.0
  describe package("xorg-x11-server-common") do
    it { should_not be_installed }
  end
  describe file("/etc/systemd/system/default.target") do
    it { should exist }
  end
  describe file("/etc/systemd/system/default.target") do
    its("basename") { should_not eq "graphical.target" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3_Disable_Avahi_Server" do
  title "Disable Avahi Server"
  desc  "
    Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.
    
    Rationale: Since servers are not normally used for printing, this service is not needed unless dependencies require it. If this is the case, disable the service to reduce the potential attack surface. If for some reason the service is required on the server, follow the recommendations in sub-sections 3.2.1 - 3.2.5 to secure it.
  "
  impact 1.0
  describe service("avahi-daemon") do
    it { should_not be_enabled }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4_Disable_Print_Server_-_CUPS" do
  title "Disable Print Server - CUPS"
  desc  "
    The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.
    
    Rationale: If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface.
  "
  impact 0.0
  describe service("cups") do
    it { should_not be_enabled }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5_Remove_DHCP_Server" do
  title "Remove DHCP Server"
  desc  "
    The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.
    
    Rationale: Unless a server is specifically set up to act as a DHCP server, it is recommended that this service be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe package("dhcp") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6_Configure_Network_Time_Protocol_NTP" do
  title "Configure Network Time Protocol (NTP)"
  desc  "
    The Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. The version of NTP delivered with CentOS can be found at [http://www.ntp.org](http://www.ntp.org). NTP can be configured to be a client and/or a server.
    
    Rationale: It is recommended that physical systems and virtual guests lacking direct access to the physical host's clock be configured as NTP clients to synchronize their clocks (especially to support time sensitive security mechanisms like Kerberos). This also ensures log files have consistent time records across the enterprise, which aids in forensic investigations.
  "
  impact 1.0
  describe file("/etc/ntp.conf") do
    its("content") { should match(/^\s*restrict\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/) }
  end
  describe file("/etc/ntp.conf") do
    its("content") { should match(/^\s*restrict\s+-6\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/) }
  end
  describe file("/etc/ntp.conf") do
    its("content") { should match(/^\s*server\s+\S+/) }
  end
  describe file("/etc/sysconfig/ntpd") do
    its("content") { should match(/^\s*OPTIONS="[^"]*-u ntp:ntp[^"]*"\s*(?:#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.7_Remove_LDAP" do
  title "Remove LDAP"
  desc  "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database. The default client/server LDAP application for CentOS is OpenLDAP.
    
    Rationale: If the server will not need to act as an LDAP client or server, it is recommended that the software be disabled to reduce the potential attack surface.
  "
  impact 0.0
  describe package("openldap-servers") do
    it { should_not be_installed }
  end
  describe package("openldap-clients") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.8_Disable_NFS_and_RPC" do
  title "Disable NFS and RPC"
  desc  "
    The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.
    
    Rationale: If the server does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface.
  "
  impact 0.0
  describe service("rpcidmapd") do
    it { should_not be_enabled }
  end
  describe service("rpcsvcgssd") do
    it { should_not be_enabled }
  end
  describe service("rpcbind") do
    it { should_not be_enabled }
  end
  describe service("rpcgssd") do
    it { should_not be_enabled }
  end
  describe service("nfslock") do
    it { should_not be_enabled }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.9_Remove_DNS_Server" do
  title "Remove DNS Server"
  desc  "
    The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.
    
    Rationale: Unless a server is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 0.0
  describe package("bind") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.10_Remove_FTP_Server" do
  title "Remove FTP Server"
  desc  "
    The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.
    
    Rationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 0.0
  describe package("vsftpd") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.11_Remove_HTTP_Server" do
  title "Remove HTTP Server"
  desc  "
    HTTP or web servers provide the ability to host web site content. The default HTTP server shipped with CentOS Linux is Apache.
    
    Rationale: Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 0.0
  describe package("httpd") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.12_Remove_Dovecot_IMAP_and_POP3_services" do
  title "Remove Dovecot (IMAP and POP3 services)"
  desc  "
    Dovecot is an open source IMAP and POP3 server for Linux based systems.
    
    Rationale: Unless POP3 and/or IMAP servers are to be provided to this server, it is recommended that the service be deleted to reduce the potential attack surface.
  "
  impact 0.0
  describe package("dovecot") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.13_Remove_Samba" do
  title "Remove Samba"
  desc  "
    The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.
    
    Rationale: If there is no need to mount directories and file systems to Windows systems, then this service can be deleted to reduce the potential attack surface.
  "
  impact 0.0
  describe package("samba") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.14_Remove_HTTP_Proxy_Server" do
  title "Remove HTTP Proxy Server"
  desc  "
    The default HTTP proxy package shipped with CentOS Linux is squid.
    
    Rationale: If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface.
  "
  impact 0.0
  describe package("squid") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.15_Remove_SNMP_Server" do
  title "Remove SNMP Server"
  desc  "
    The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.
    
    Rationale: The SNMP server communicates using SNMP v1, which transmits data in the clear and does not require authentication to execute commands. Unless absolutely necessary, it is recommended that the SNMP service not be used.
  "
  impact 0.0
  describe package("net-snmp") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.16_Configure_Mail_Transfer_Agent_for_Local-Only_Mode" do
  title "Configure Mail Transfer Agent for Local-Only Mode"
  desc  "
    Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail. By default, the MTA is set to loopback mode on CentOS.
    
    Rationale: The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems.
  "
  impact 1.0
  describe port(25).where { protocol =~ /.*/ && address =~ /^(?!127\.0\.0\.1|::1).*$/ } do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1_Disable_IP_Forwarding" do
  title "Disable IP Forwarding"
  desc  "
    The net.ipv4.ip_forward flag is used to tell the server whether it can forward packets or not. If the server is not to be used as a router, set the flag to 0.
    
    Rationale: Setting the flag to 0 ensures that a server with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.2_Disable_Send_Packet_Redirects" do
  title "Disable Send Packet Redirects"
  desc  "
    ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.
    
    Rationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1_Disable_Source_Routed_Packet_Acceptance" do
  title "Disable Source Routed Packet Acceptance"
  desc  "
    In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.
    
    Rationale: Setting net.ipv4.conf.all.accept_source_route and net.ipv4.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this server was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the server as a way to reach the private address servers. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2_Disable_ICMP_Redirect_Acceptance" do
  title "Disable ICMP Redirect Acceptance"
  desc  "
    ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables.
    
    Rationale: Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_redirects") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.4_Log_Suspicious_Packets" do
  title "Log Suspicious Packets"
  desc  "
    When enabled, this feature logs packets with un-routable source addresses to the kernel log.
    
    Rationale: Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their server.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should eq 1 }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.5_Enable_Ignore_Broadcast_Requests" do
  title "Enable Ignore Broadcast Requests"
  desc  "
    Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.
    
    Rationale: Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.6_Enable_Bad_Error_Message_Protection" do
  title "Enable Bad Error Message Protection"
  desc  "
    Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.
    
    Rationale: Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.8_Enable_TCP_SYN_Cookies" do
  title "Enable TCP SYN Cookies"
  desc  "
    When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the server to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.
    
    Rationale: Attackers use SYN flood attacks to perform a denial of service attacked on a server by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the server to keep accepting valid connections, even if under a denial of service attack.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.3.1_Deactivate_Wireless_Interfaces" do
  title "Deactivate Wireless Interfaces"
  desc  "
    Wireless networking is used when wired networks are unavailable. CentOS contains a wireless tool kit to allow system administrators to configure and use wireless networks.
    
    Rationale: If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4.1.1_Disable_IPv6_Router_Advertisements" do
  title "Disable IPv6 Router Advertisements"
  desc  "
    This setting disables the systems ability to accept router advertisements
    
    Rationale: It is recommended that systems not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4.1.2_Disable_IPv6_Redirect_Acceptance" do
  title "Disable IPv6 Redirect Acceptance"
  desc  "
    This setting prevents the system from accepting ICMP redirects. ICMP redirects tell the system about alternate routes for sending traffic.
    
    Rationale: It is recommended that systems not accept ICMP redirects as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4.2_Disable_IPv6" do
  title "Disable IPv6"
  desc  "
    Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6.
    
    Rationale: If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.1_Install_TCP_Wrappers" do
  title "Install TCP Wrappers"
  desc  "
    TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so library attached to it.
    
    Rationale: TCP Wrappers provide a good simple access list mechanism to services that may not have that support built in. It is recommended that all services that can support TCP Wrappers, use it.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.2_Create_etchosts.allow" do
  title "Create /etc/hosts.allow"
  desc  "
    The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.deny file.
    
    Rationale: The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized systems can connect to the server.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.3_Verify_Permissions_on_etchosts.allow" do
  title "Verify Permissions on /etc/hosts.allow"
  desc  "
    The /etc/hosts.allow file contains networking information that is used by many applications and therefore must be readable for these applications to operate.
    
    Rationale: It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/hosts.allow") do
    it { should exist }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.4_Create_etchosts.deny" do
  title "Create /etc/hosts.deny"
  desc  "
    The /etc/hosts.deny file specifies which IP addresses are **not** permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.allow file.
    
    Rationale: The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow is denied access to the server.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.5_Verify_Permissions_on_etchosts.deny" do
  title "Verify Permissions on /etc/hosts.deny"
  desc  "
    The /etc/hosts.deny file contains network information that is used by many system applications and therefore must be readable for these applications to operate.
    
    Rationale: It is critical to ensure that the /etc/hosts.deny file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/hosts.deny") do
    it { should exist }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.1_Disable_DCCP" do
  title "Disable DCCP"
  desc  "
    The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.
    
    Rationale: If the protocol is not required, it is recommended that the drivers not be installed
    to reduce the potential attack surface.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.2_Disable_SCTP" do
  title "Disable SCTP"
  desc  "
    The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.
    
    Rationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.3_Disable_RDS" do
  title "Disable RDS"
  desc  "
    The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.
    
    Rationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.4_Disable_TIPC" do
  title "Disable TIPC"
  desc  "
    The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.
    
    Rationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.7_Enable_firewalld" do
  title "Enable firewalld"
  desc  "
    IPtables is an application that allows a system administrator to configure the IP tables, chains and rules provided by the Linux kernel firewall.  The firewalld service provides a dynamic firewall allowing changes to be made at anytime without disruptions cause by reloading.
    
    Rationale: A firewall provides extra protection for the Linux system by limiting communications in and out of the box to specific addresses and ports.
  "
  impact 1.0
  describe service("firewalld") do
    it { should be_enabled }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.1_Install_the_rsyslog_package" do
  title "Install the rsyslog package"
  desc  "
    The rsyslog package is a third party package that provides many enhancements to syslog, such as multi-threading, TCP communication, message filtering and data base support.
    
    Rationale: The security enhancements of rsyslog such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package.
  "
  impact 1.0
  describe package("rsyslog") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.2_Activate_the_rsyslog_Service" do
  title "Activate the rsyslog Service"
  desc  "
    The systemctl command can be used to ensure that the rsyslog service is turned on.
    
    Rationale: If the rsyslog service is not activated the system will not have a syslog service running.
  "
  impact 1.0
  describe service("rsyslog") do
    it { should be_enabled }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.3_Configure_etcrsyslog.conf" do
  title "Configure /etc/rsyslog.conf"
  desc  "
    The /etc/rsyslog.conf file specifies rules for logging and which files are to be used to log certain classes of messages.
    
    Rationale: A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.).
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.4_Create_and_Set_Permissions_on_rsyslog_Log_Files" do
  title "Create and Set Permissions on rsyslog Log Files"
  desc  "
    A log file must already exist for rsyslog to be able to write to it.
    
    Rationale: It is important to ensure that log files exist and have the correct permissions to ensure that sensitive rsyslog data is archived and protected.
  "
  impact 1.0
  file("/etc/rsyslog.conf").content.to_s.scan(/^[^#$\r\n](.*\s+\/.*)$/).flatten.map { |x| x.scan(/^[^#$\r\n].*\s+(\/.*)$/) }.flatten.each do |entry|
    describe file(entry) do
      it { should exist }
    end
    describe file(entry) do
      it { should_not be_executable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_executable.by "other" }
    end
    describe file(entry) do
      it { should_not be_readable.by "other" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.5_Configure_rsyslog_to_Send_Logs_to_a_Remote_Log_Host" do
  title "Configure rsyslog to Send Logs to a Remote Log Host"
  desc  "
    The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to receive messages from remote hosts, reducing administrative overhead.
    
    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system
  "
  impact 1.0
  describe file("/etc/rsyslog.conf") do
    its("content") { should match(/^\*\.\*\s+@/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.6_Accept_Remote_rsyslog_Messages_Only_on_Designated_Log_Hosts" do
  title "Accept Remote rsyslog Messages Only on Designated Log Hosts"
  desc  "
    By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port.
    
    Rationale: The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts within the specified domain and that those systems that are not designed to be log hosts do not accept any remote rsyslog messages. This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete syslog data in a central location.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3_Configure_logrotate" do
  title "Configure logrotate"
  desc  "
    The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageable large. The file /etc/logrotate.d/syslog is the configuration file used to rotate log files created by syslog or rsyslog. These files are rotated on a weekly basis via a cron job and the last 4 weeks are kept.
    
    Rationale: By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.1_Enable_anacron_Daemon" do
  title "Enable anacron Daemon"
  desc  "
    The anacron daemon is used on systems that are not up 24x7. The anacron daemon will execute jobs that would have normally been run had the system not been down.
    
    Rationale: Cron jobs may include critical security or administrative functions that need to run on a regular basis. Use this daemon on machines that are not up 24x7, or if there are jobs that need to be executed after the system has been brought back up after a maintenance window.
  "
  impact 1.0
  describe package("cronie-anacron") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.2_Enable_crond_Daemon" do
  title "Enable crond Daemon"
  desc  "
    The crond daemon is used to execute batch jobs on the system.
    
    Rationale: While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run and crond is used to execute them.
  "
  impact 1.0
  describe service("crond") do
    it { should be_enabled }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.3_Set_UserGroup_Owner_and_Permission_on_etcanacrontab" do
  title "Set User/Group Owner and Permission on /etc/anacrontab"
  desc  "
    The /etc/anacrontab file is used by anacron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and is the only user that can read and write the file.
    
    Rationale: This file contains information on what system jobs are run by anacron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access.
  "
  impact 1.0
  describe file("/etc/anacrontab") do
    it { should exist }
  end
  describe file("/etc/anacrontab") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/anacrontab") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/anacrontab") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/anacrontab") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/anacrontab") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/anacrontab") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/anacrontab") do
    it { should exist }
  end
  describe file("/etc/anacrontab") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/anacrontab") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.4_Set_UserGroup_Owner_and_Permission_on_etccrontab" do
  title "Set User/Group Owner and Permission on /etc/crontab"
  desc  "
    The /etc/crontab file is used by cron to control its own jobs. The commands in this item make here sure that root is the user and group owner of the file and is the only user that can read and write the file.
    
    Rationale: This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access.
  "
  impact 1.0
  describe file("/etc/crontab") do
    it { should exist }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should exist }
  end
  describe file("/etc/crontab") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/crontab") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.5_Set_UserGroup_Owner_and_Permission_on_etccron.hourly" do
  title "Set User/Group Owner and Permission on /etc/cron.hourly"
  desc  "
    This directory contains system cron jobs that need to run on an hourly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.hourly") do
    it { should exist }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should exist }
  end
  describe file("/etc/cron.hourly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.hourly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.6_Set_UserGroup_Owner_and_Permission_on_etccron.daily" do
  title "Set User/Group Owner and Permission on /etc/cron.daily"
  desc  "
    The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.daily") do
    it { should exist }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should exist }
  end
  describe file("/etc/cron.daily") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.daily") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.7_Set_UserGroup_Owner_and_Permission_on_etccron.weekly" do
  title "Set User/Group Owner and Permission on /etc/cron.weekly"
  desc  "
    The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.weekly") do
    it { should exist }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should exist }
  end
  describe file("/etc/cron.weekly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.weekly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.8_Set_UserGroup_Owner_and_Permission_on_etccron.monthly" do
  title "Set User/Group Owner and Permission on /etc/cron.monthly"
  desc  "
    The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.monthly") do
    it { should exist }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should exist }
  end
  describe file("/etc/cron.monthly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.monthly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.9_Set_UserGroup_Owner_and_Permission_on_etccron.d" do
  title "Set User/Group Owner and Permission on /etc/cron.d"
  desc  "
    The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, daily weekly and monthly jobs from /etc/crontab, but require more granular control as to when they run. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.d") do
    it { should exist }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should exist }
  end
  describe file("/etc/cron.d") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.d") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.10_Restrict_at_Daemon" do
  title "Restrict at Daemon"
  desc  "
    The at daemon works with the cron daemon to allow non-privileged users to submit one time only jobs at their convenience. There are two files that control at: /etc/at.allow and /etc/at.deny. If /etc/at.allow exists, then users listed in the file are the only ones that can create at jobs. If /etc/at.allow does not exist and /etc/at.deny does exist, then any user on the system, with the exception of those listed in /etc/at.deny, are allowed to execute at jobs. An empty /etc/at.deny file allows any user to create at jobs. If neither /etc/at.allow nor /etc/at.deny exist, then only superuser can create at jobs. The commands below remove the /etc/at.deny file and create an empty /etc/at.allow file that can only be read and modified by user and group root.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means to gain unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls. In addition, it is a better practice to create a white list of users who can execute at jobs versus a blacklist of users who can't execute at jobs as a system administrator will always know who can create jobs and does not have to worry about remembering to add a user to the blacklist when a new user id is created.
  "
  impact 1.0
  describe file("/etc/at.deny") do
    it { should_not exist }
  end
  describe file("/etc/at.allow") do
    it { should exist }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should exist }
  end
  describe file("/etc/at.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.11_Restrict_atcron_to_Authorized_Users" do
  title "Restrict at/cron to Authorized Users"
  desc  "
    Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services. If /etc/cron.allow or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked. Any user not specifically defined in those files is allowed to use at and cron. By removing the files, only users in /etc/cron.allow and /etc/at.allow are allowed to use at and cron. Note that even though a given user is not listed in cron.allow, cron jobs can still be run as that user. The cron.allow file only controls administrative access to the crontab command for scheduling and modifying cron jobs.
    
    Rationale: On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  impact 1.0
  describe file("/etc/cron.deny") do
    it { should_not exist }
  end
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.allow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.1_Set_SSH_Protocol_to_2" do
  title "Set SSH Protocol to 2"
  desc  "
    SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure.
    
    Rationale: SSH v1 suffers from insecurities that do not affect SSH v2.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "2" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.2_Set_LogLevel_to_INFO" do
  title "Set LogLevel to INFO"
  desc  "
    The INFO parameter specifies that login and logout activity will be logged.
    
    Rationale: SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically **not** recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information. INFO level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "INFO" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.3_Set_Permissions_on_etcsshsshd_config" do
  title "Set Permissions on /etc/ssh/sshd_config"
  desc  "
    The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets the owner and group of the file to root.
    
    Rationale: The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    it { should exist }
  end
  describe file("/etc/ssh/sshd_config") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/ssh/sshd_config") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should exist }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.4_Disable_SSH_X11_Forwarding" do
  title "Disable SSH X11 Forwarding"
  desc  "
    The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.
    
    Rationale: Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.5_Set_SSH_MaxAuthTries_to_4_or_Less" do
  title "Set SSH MaxAuthTries to 4 or Less"
  desc  "
    The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file detailing the login failure.
    
    Rationale: Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, it is set the number based on site policy.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 4 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes" do
  title "Set SSH IgnoreRhosts to Yes"
  desc  "
    The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication.
    
    Rationale: Setting this parameter forces users to enter a password when authenticating with ssh.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.7_Set_SSH_HostbasedAuthentication_to_No" do
  title "Set SSH HostbasedAuthentication to No"
  desc  "
    The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with successful public key client host authentication. This option only applies to SSH Protocol Version 2.
    
    Rationale: Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an additional layer of protection .
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.8_Disable_SSH_Root_Login" do
  title "Disable SSH Root Login"
  desc  "
    The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no.
    
    Rationale: Disallowing root logins over SSH requires server admins to authenticate using their own individual account, then escalating to root via sudo or su. This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.9_Set_SSH_PermitEmptyPasswords_to_No" do
  title "Set SSH PermitEmptyPasswords to No"
  desc  "
    The PermitEmptyPasswords parameter specifies if the server allows login to accounts with empty password strings.
    
    Rationale: Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.10_Do_Not_Allow_Users_to_Set_Environment_Options" do
  title "Do Not Allow Users to Set Environment Options"
  desc  "
    The PermitUserEnvironment option allows users to present environment options to the ssh daemon.
    
    Rationale: Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has ssh executing trojaned programs).
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.11_Use_Only_Approved_Cipher_in_Counter_Mode" do
  title "Use Only Approved Cipher in Counter Mode"
  desc  "
    This variable limits the types of ciphers that SSH can use during communication.
    
    Rationale: Based on research conducted at various institutions, it was determined that the symmetric portion of the SSH Transport Protocol (as described in RFC 4253) has security weaknesses that allowed recovery of up to 32 bits of plaintext from a block of ciphertext that was encrypted with the Cipher Block Chaining (CBC) method. From that research, new Counter mode algorithms (as described in RFC4344) were designed that are not vulnerable to these types of attacks and these algorithms are now recommended for standard use.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Ciphers\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Ciphers\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "aes128-ctr,aes192-ctr,aes256-ctr" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.12_Set_Idle_Timeout_Interval_for_User_Login" do
  title "Set Idle Timeout Interval for User Login"
  desc  "
    The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length of time are terminated. When the ClientAliveCountMax variable is set, sshd will send client alive messages at every ClientAliveInterval interval. When the number of consecutive client alive messages are sent with no response from the client, the ssh session is terminated. For example, if the ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session will be terminated after 45 seconds of idle time.
    
    Rationale: Having no timeout value associated with a connection could allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value at least reduces the risk of this happening..
    
    While the recommended setting is 300 seconds (5 minutes), set this timeout value based on site policy. The recommended setting for ClientAliveCountMax is 0. In this case, the client session will be terminated after 5 minutes of idle time and no keepalive messages will be sent.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp == 300 }
    end
  end
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp == 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.13_Limit_Access_via_SSH" do
  title "Limit Access via SSH"
  desc  "
    There are several options available to limit which users and group can access the system via SSH. It is recommended that at least of the following options be leveraged:
    
    AllowUsers
    
    The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list consists of comma separated user names. Numeric userIDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.
    
    AllowGroups
    
    The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. The list consists of comma separated user names. Numeric groupIDs are not recognized with this variable.
    
    DenyUsers
    
    The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list consists of comma separated user names. Numeric userIDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.
    
    DenyGroups
    
    The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. The list consists of comma separated group names. Numeric groupIDs are not recognized with this variable.
    
    Rationale: Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.14_Set_SSH_Banner" do
  title "Set SSH Banner"
  desc  "
    The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.
    
    Rationale: Banners are used to warn connecting users of the particular site's policy regarding connection. Consult with your legal department for the appropriate warning banner for your site.
  "
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Banner\s+(\S+)\s*(?:#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.1_Upgrade_Password_Hashing_Algorithm_to_SHA-512" do
  title "Upgrade Password Hashing Algorithm to SHA-512"
  desc  "
    The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.
    
    Rationale: The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords.
    
    Note that these change only apply to accounts configured on the local system.
  "
  impact 1.0
  describe file("/etc/libuser.conf") do
    its("content") { should match(/^[\s]*crypt_style[\s]+=[\s]+(?i)sha512[\s]*$/) }
  end
  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*ENCRYPT_METHOD[\s]+SHA512[\s]*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^[\s]*password[\s]+(?:(?:required)|(?:sufficient))[\s]+pam_unix\.so[\s]+.*sha512.*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.2_Set_Password_Creation_Requirement_Parameters_Using_pam_pwquality" do
  title "Set Password Creation Requirement Parameters Using pam_pwquality"
  desc  "
    The pam_pwquality module checks of the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the pam_pwquality.so options.
    
    * try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.
    * retry=3- Allow 3 tries before sending back a failure.
    The following options are set in the /etc/security/pwquality.conf file:
    
    * minlen=14 - password must be 14 characters or more
    * dcredit=-1 - provide at least 1 digit
    * ucredit=-1 - provide at least one uppercase character
    * ocredit=-1 - provide at least one special character
    * lcredit=-1 - provide at least one lowercase character
    The setting shown above is one possible policy. Alter these values to conform to your own organization's password policies.
    
    Rationale: Strong passwords protect systems from being hacked through brute force methods.
  "
  impact 1.0
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:required|requisite)\s+pam_pwquality.so\s+(?:\S+\s+)*try_first_pass(?:\s+\S+)*\s*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:required|requisite)\s+pam_pwquality.so\s+(?:\S+\s+)*retry=[123](?:\s+\S+)*\s*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\s*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*dcredit\s*=\s*-[1-9][0-9]*\s*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ucredit\s*=\s*-[1-9][0-9]*\s*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ocredit\s*=\s*-[1-9][0-9]*\s*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*lcredit\s*=\s*-[1-9][0-9]*\s*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.3_Set_Lockout_for_Failed_Password_Attempts" do
  title "Set Lockout for Failed Password Attempts"
  desc  "
    Lock out userIDs after **n** unsuccessful consecutive login attempts. The first sets of changes are made to the main PAM configuration files /etc/pam.d/system-auth and /etc/pam.d/password-auth. The second set of changes are applied to the program specific PAM configuration file (in this case, the ssh daemon). The second set of changes must be applied to each program that will lock out userID's.
    
    Set the lockout number to the policy in effect at your site.
    
    Rationale: Locking out userIDs after **n** unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.4_Limit_Password_Reuse" do
  title "Limit Password Reuse"
  desc  "
    The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.
    
    Rationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password.
    
    Note that these change only apply to accounts configured on the local system.
  "
  impact 1.0
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+sufficient\s+pam_unix.so(\s+[^\s]+)*\s+remember=5(\s+[^\s]+)*\s*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.4_Restrict_root_Login_to_System_Console" do
  title "Restrict root Login to System Console"
  desc  "
    The file /etc/securetty contains a list of valid terminals that may be logged in directly as root.
    
    Rationale: Since the system console has special properties to handle emergency situations, it is important to ensure that the console is in a physically secure location and that unauthorized consoles have not been defined.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.5_Restrict_Access_to_the_su_Command" do
  title "Restrict Access to the su Command"
  desc  "
    The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su, the su command will only allow users in the wheel group to execute su.
    
    Rationale: Restricting the use of su, and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo, whereas su can only record that a user executed the su program.
  "
  impact 1.0
  describe file("/etc/pam.d/su") do
    its("content") { should match(/^\s*auth\s+required\s+pam_wheel.so\s+use_uid\s*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.1.1_Set_Password_Expiration_Days" do
  title "Set Password Expiration Days"
  desc  "
    The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 90 days.
    
    Rationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity.
  "
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^PASS_MAX_DAYS\s+(90|[1-7][0-9]|[1-9])$/) }
  end
  shadow.users(/.*/).entries.each do |entry|
    describe entry do
      its("max_days") { should cmp <= 90 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.1.2_Set_Password_Change_Minimum_Number_of_Days" do
  title "Set Password Change Minimum Number of Days"
  desc  "
    The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing their password until a minimum number of days have passed since the last time the user changed their password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.
    
    Rationale: By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls.
  "
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^PASS_MIN_DAYS\s+([7-9]|[1-9][0-9]+)$/) }
  end
  shadow.users(/.*/).entries.each do |entry|
    describe entry do
      its("min_days") { should cmp >= 7 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.1.3_Set_Password_Expiring_Warning_Days" do
  title "Set Password Expiring Warning Days"
  desc  "
    The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE parameter be set to 7 or more days.
    
    Rationale: Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered.
  "
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^PASS_WARN_AGE\s+([7-9]|[1-9][0-9]+)$/) }
  end
  shadow.users(/.*/).entries.each do |entry|
    describe entry do
      its("warn_days") { should cmp >= 7 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.2_Disable_System_Accounts" do
  title "Disable System Accounts"
  desc  "
    There are a number of accounts provided with the CentOS that are used to manage applications and are not intended to provide an interactive shell.
    
    Rationale: It is important to make sure that accounts that are not being used by regular users are locked to prevent them from being used to provide an interactive shell. By default, CentOS sets the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin. This prevents the account from potentially being used to run any commands.
  "
  impact 1.0
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ && uid.to_i < 1000 && shell != "/sbin/nologin" } do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.3_Set_Default_Group_for_root_Account" do
  title "Set Default Group for root Account"
  desc  "
    The usermod command can be used to specify which group the root user belongs to. This affects permissions of files that are created by the root user.
    
    Rationale: Using GID 0 for the **root**account helps prevent **root**-owned files from accidentally becoming accessible to non-privileged users.
  "
  impact 1.0
  describe passwd.where { user == "root" } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user == "root" && gid.to_i == 0 } do
    its("entries") { should_not be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.4_Set_Default_umask_for_Users" do
  title "Set Default umask for Users"
  desc  "
    The default umask determines the permissions of files created by users. The user creating the file has the discretion of making their files and directories readable by others via the chmod command. Users who wish to allow their files and directories to be readable by others by default may choose a different default umask by inserting the umask command into the standard shell configuration files (.profile, .cshrc, etc.) in their home directories.
    
    Rationale: Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions. A default umask setting of 077 causes files and directories created by users to not be readable by any other user on the system. A umask of 027 would make files and directories readable by users in the same Unix group, while a umask of 022 would make files readable by every user on the system.
    
    **Note:** The directives in this section apply to bash and shell. If other shells are supported on the system, it is recommended that their configuration files also are checked.
  "
  impact 1.0
  describe file("/etc/bashrc") do
    its("content") { should match(/^\s*umask\s+077\s*$/) }
  end
  command("find /etc/profile.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should match(/^\s*umask\s+077\s*$/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts" do
  title "Lock Inactive User Accounts"
  desc  "
    User accounts that have been inactive for over a given period of time can be automatically disabled. It is recommended that accounts that are inactive for 35 or more days be disabled.
    
    Rationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.
  "
  impact 1.0
  describe file("/etc/default/useradd") do
    its("content") { should match(/^INACTIVE=35$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_8.1_Set_Warning_Banner_for_Standard_Login_Services" do
  title "Set Warning Banner for Standard Login Services"
  desc  "
    The contents of the /etc/issue file are displayed prior to the login prompt on the system's console and serial devices, and also prior to logins via telnet. The contents of the /etc/motd file is generally displayed after all successful logins, no matter where the user is logging in from, but is thought to be less useful because it only provides notification to the user after the machine has been accessed.
    
    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Consult with your organization's legal counsel for the appropriate wording for your specific organization.
  "
  impact 1.0
  describe file("/etc/motd") do
    it { should exist }
  end
  describe file("/etc/motd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/motd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/motd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/motd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/motd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should be_writable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should exist }
  end
  describe file("/etc/motd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/motd") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should exist }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should be_writable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should exist }
  end
  describe file("/etc/issue") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should exist }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should be_writable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should exist }
  end
  describe file("/etc/issue.net") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_8.2_Remove_OS_Information_from_Login_Warning_Banners" do
  title "Remove OS Information from Login Warning Banners"
  desc  "
    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information:
    
    \\m - machine architecture (uname -m)
    \\r - operating system release (uname -r)
    \\s - operating system name
    \\v - operating system version (uname -v)
    
    Rationale: Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in.
  "
  impact 1.0
  describe file("/etc/motd") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
  describe file("/etc/issue") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
  describe file("/etc/issue.net") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_8.3_Set_GNOME_Warning_Banner" do
  title "Set GNOME Warning Banner"
  desc  "
    The GNOME Display Manager is used for login session management. See the manual page gdm(1) for more information. The remediation action for this item sets a warning message for GDM users before they log in.
    
    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Consult with your organization's legal counsel for the appropriate wording for your specific organization.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.2_Verify_Permissions_on_etcpasswd" do
  title "Verify Permissions on /etc/passwd"
  desc  "
    The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.
    
    Rationale: It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.3_Verify_Permissions_on_etcshadow" do
  title "Verify Permissions on /etc/shadow"
  desc  "
    The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts.
  "
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow") do
    it { should_not be_readable.by "owner" }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.4_Verify_Permissions_on_etcgshadow" do
  title "Verify Permissions on /etc/gshadow"
  desc  "
    The /etc/gshadow file contains information about group accounts that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as expiration) could also be useful to subvert the group accounts.
  "
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "owner" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.5_Verify_Permissions_on_etcgroup" do
  title "Verify Permissions on /etc/group"
  desc  "
    The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.
    
    Rationale: The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  impact 1.0
  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.6_Verify_UserGroup_Ownership_on_etcpasswd" do
  title "Verify User/Group Ownership on /etc/passwd"
  desc  "
    The /etc/passwd file contains a list of all the valid userIDs defined in the system, but not the passwords. The command below sets the owner and group of the file to root.
    
    Rationale: The /etc/passwd file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.7_Verify_UserGroup_Ownership_on_etcshadow" do
  title "Verify User/Group Ownership on /etc/shadow"
  desc  "
    The /etc/shadow file contains the one-way cipher text passwords for each user defined in the /etc/passwd file. The command below sets the user and group ownership of the file to root.
    
    Rationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts.
  "
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/shadow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.8_Verify_UserGroup_Ownership_on_etcgshadow" do
  title "Verify User/Group Ownership on /etc/gshadow"
  desc  "
    The /etc/gshadow file contains information about group accounts that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as expiration) could also be useful to subvert the group accounts.
  "
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.9_Verify_UserGroup_Ownership_on_etcgroup" do
  title "Verify User/Group Ownership on /etc/group"
  desc  "
    The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.
    
    Rationale: The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  impact 1.0
  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.10_Find_World_Writable_Files" do
  title "Find World Writable Files"
  desc  "
    Unix-based systems support variable settings to control access to files. World writable files are the least secure. See the chmod(2) man page for more information.
    
    Rationale: Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.11_Find_Un-owned_Files_and_Directories" do
  title "Find Un-owned Files and Directories"
  desc  "
    Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system.
    
    Rationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended.
  "
  impact 1.0
  describe command("find / -regex .\\*/.\\* -type f -nouser -xdev") do
    its("stdout") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.12_Find_Un-grouped_Files_and_Directories" do
  title "Find Un-grouped Files and Directories"
  desc  "
    Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system.
    
    Rationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended.
  "
  impact 1.0
  describe command("find / -regex .\\*/.\\* -type f -nogroup -xdev") do
    its("stdout") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.13_Find_SUID_System_Executables" do
  title "Find SUID System Executables"
  desc  "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID program is to enable users to perform functions (such as changing their password) that require root privileges.
    
    Rationale: There are valid reasons for SUID programs, but it is important to identify and review such programs to ensure they are legitimate.
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.14_Find_SGID_System_Executables" do
  title "Find SGID System Executables"
  desc  "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SGID program is to enable users to perform functions (such as changing their password) that require root privileges.
    
    Rationale: There are valid reasons for SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different md5 checksum than what from the package. This is an indication that the binary may have been replaced. The following is an example of checking the \"sudo\" executable:
    
    # rpm -V `rpm -qf /usr/bin/sudo`
    .......T /usr/bin/sudo
    SM5....T /usr/bin/sudoedit
  "
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.1_Ensure_Password_Fields_are_Not_Empty" do
  title "Ensure Password Fields are Not Empty"
  desc  "
    An account with an empty password field means that anybody may log in as that user without providing a password.
    
    Rationale: All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
  "
  impact 1.0
  shadow.users(/.*/).entries.each do |entry|
    describe entry do
      its("passwords") { should match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.2_Verify_No_Legacy__Entries_Exist_in_etcpasswd_File" do
  title "Verify No Legacy \"+\" Entries Exist in /etc/passwd File"
  desc  "
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on CentOS 7 systems, but may exist in files that have been imported from other platforms.
    
    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  "
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.3_Verify_No_Legacy__Entries_Exist_in_etcshadow_File" do
  title "Verify No Legacy \"+\" Entries Exist in /etc/shadow File"
  desc  "
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on CentOS 7 systems, but may exist in files that have been imported from other platforms.
    
    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  "
  impact 1.0
  describe file("/etc/shadow") do
    its("content") { should_not match(/^+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.4_Verify_No_Legacy__Entries_Exist_in_etcgroup_File" do
  title "Verify No Legacy \"+\" Entries Exist in /etc/group File"
  desc  "
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on CentOS 7 systems, but may exist in files that have been imported from other platforms.
    
    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  "
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.5_Verify_No_UID_0_Accounts_Exist_Other_Than_root" do
  title "Verify No UID 0 Accounts Exist Other Than root"
  desc  "
    Any account with UID 0 has superuser privileges on the system.
    
    Rationale: This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 7.5 Restrict root Login to System Console.
  "
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^(?!root:)[^:]*:[^:]*:0/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.6_Ensure_root_PATH_Integrity" do
  title "Ensure root PATH Integrity"
  desc  "
    The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH is not set correctly.
    
    Rationale: Including the current working directory (.) or other writable directory in root's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program.
  "
  impact 1.0
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
      it { should_not eq "" }
    end
  end
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
      it { should_not eq "." }
    end
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe file(entry) do
      it { should exist }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
    describe file(entry) do
      its("uid") { should cmp 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.7_Check_Permissions_on_User_Home_Directories" do
  title "Check Permissions on User Home Directories"
  desc  "
    While the system administrator can establish secure permissions for users' home directories, the users can easily override these.
    
    Rationale: Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.each do |entry|
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_executable.by "other" }
    end
    describe file(entry) do
      it { should_not be_readable.by "other" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.8_Check_User_Dot_File_Permissions" do
  title "Check User Dot File Permissions"
  desc  "
    While the system administrator can establish secure permissions for users' \"dot\" files, the users can easily override these.
    
    Rationale: Group or world-writable user configuration files may enable malicious users to steal or modify other users' data or to gain another user's system privileges.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| command("find #{x} -maxdepth 1 -type f -regex '.*/\..+'").stdout.split }.flatten.each do |entry|
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.9_Check_Permissions_on_User_.netrc_Files" do
  title "Check Permissions on User .netrc Files"
  desc  "
    While the system administrator can establish secure permissions for users' .netrc files, the users can easily override these.
    
    Rationale: .netrc files may contain unencrypted passwords that may be used to attack other systems.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".netrc"}.each do |entry|
    describe file(entry) do
      it { should_not be_executable.by "group" }
    end
    describe file(entry) do
      it { should_not be_readable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_executable.by "other" }
    end
    describe file(entry) do
      it { should_not be_readable.by "other" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.10_Check_for_Presence_of_User_.rhosts_Files" do
  title "Check for Presence of User .rhosts Files"
  desc  "
    While no .rhosts files are shipped with CentOS 7, users can easily create them.
    
    Rationale: This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf. Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, they may have been brought over from other systems and could contain information useful to an attacker for those other systems.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".rhosts"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.11_Check_Groups_in_etcpasswd" do
  title "Check Groups in /etc/passwd"
  desc  "
    Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group.
    
    Rationale: Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group permissions are not properly managed.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.gids.map { |x| "^[^:]*:[^:]*:" + x.to_s }.map { |x| x.to_s + ":[^:]*$" }.each do |entry|
    describe file("/etc/group") do
      its("content") { should match Regexp.new(entry) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.12_Check_That_Users_Are_Assigned_Valid_Home_Directories" do
  title "Check That Users Are Assigned Valid Home Directories"
  desc  "
    Users can be defined in /etc/passwd without a home directory or with a home directory does not actually exist.
    
    Rationale: If the user's home directory does not exist or is unassigned, the user will be placed in \"/\" and will not be able to write any files or have local environment variables set.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.each do |entry|
    describe file(entry) do
      it { should exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.13_Check_User_Home_Directory_Ownership" do
  title "Check User Home Directory Ownership"
  desc  "
    The user home directory is space defined for the particular user to set local environment variables and to store personal files.
    
    Rationale: Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory.
  "
  impact 1.0
  passwd.where { uid.to_i >= 1000 && user != 'nfsnobody' }.entries.each do |entry|
    describe.one do
      describe file(entry.home) do
        it { should_not exist }
      end
      describe file(entry.home) do
        it { should be_owned_by entry.user }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.14_Check_for_Duplicate_UIDs" do
  title "Check for Duplicate UIDs"
  desc  "
    Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the /etc/passwd file and change the UID field.
    
    Rationale: Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
  "
  impact 1.0
  describe passwd.where { user =~ /.*/ }.uids do
    its("length") { should_not eq 0 }
  end
  a = passwd.where { user =~ /.*/ }.uids.uniq.length
  describe passwd.where { user =~ /.*/ }.uids do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.15_Check_for_Duplicate_GIDs" do
  title "Check for Duplicate GIDs"
  desc  "
    Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the /etc/group file and change the GID field.
    
    Rationale: User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
    
    **Note:** In the case of extremely large groups it can become necessary to split a GID across group names due to character limits per line.  Any such instances should be carefully audited, unless absolutely necessary such instances should be avoided.
  "
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.16_Check_That_Reserved_UIDs_Are_Assigned_to_System_Accounts" do
  title "Check That Reserved UIDs Are Assigned to System Accounts"
  desc  "
    Traditionally, UNIX systems establish \"reserved\" UIDs (0-999 range) that are intended for system accounts.
    
    Rationale: If a user is assigned a UID that is in the reserved range, even if it is not presently in use, security exposures can arise if a subsequently installed application uses the same UID.
  "
  impact 1.0
  describe passwd.where { user =~ /^(?!root|bin|daemon|adm|lp|sync|shutdown|halt|mail|news|uucp|operator|games|gopher|ftp|nobody|nscd|vcsa|rpc|mailnull|smmsp|pcap|ntp|dbus|avahi|sshd|rpcuser|nfsnobody|haldaemon|avahi-autoipd|distcache|apache|oprofile|webalizer|dovecot|squid|named|xfs|gdm|sabayon|usbmuxd|rtkit|abrt|saslauth|pulse|postfix|tcpdump).*$/ } do
    its("entries") { should_not be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.17_Check_for_Duplicate_User_Names" do
  title "Check for Duplicate User Names"
  desc  "
    Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually edit the /etc/passwd file and change the user name.
    
    Rationale: If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd. For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem.
  "
  impact 1.0
  describe passwd.where { user =~ /.*/ }.users do
    its("length") { should_not eq 0 }
  end
  a = passwd.where { user =~ /.*/ }.users.uniq.length
  describe passwd.where { user =~ /.*/ }.users do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.18_Check_for_Duplicate_Group_Names" do
  title "Check for Duplicate Group Names"
  desc  "
    Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group file and change the group name.
    
    Rationale: If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group. Effectively, the GID is shared, which is a security problem.
  "
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.19_Check_for_Presence_of_User_.netrc_Files" do
  title "Check for Presence of User .netrc Files"
  desc  "
    The .netrc file contains data for logging into a remote host for file transfers via FTP.
    
    Rationale: The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is disabled, user accounts may have brought over .netrc files from other systems which could pose a risk to those systems.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".netrc"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.20_Check_for_Presence_of_User_.forward_Files" do
  title "Check for Presence of User .forward Files"
  desc  "
    The .forward file specifies an email address to forward the user's mail to.
    
    Rationale: Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization. The .forward file also poses a risk as it can be used to execute commands that may perform unintended actions.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".forward"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end