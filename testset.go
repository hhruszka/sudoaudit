package main

var sudo = `Matching Defaults entries for lss on sbclcm-oam-a:
    use_pty, !lecture, !mailerpath, syslog_badpri=notice, !authenticate, env_reset, logfile=/var/log/sudo,
    secure_path=/opt/RCC/bin\:/opt/LSS/sbin\:/opt/LSS/bin\:/opt/LU3P/sbin\:/opt/LU3P/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/usr/java/bin, env_keep+="RCCBASEDIR RCC_OS RCC_WDPORT RCCOUTFILE RCCERRFILE
    RCCSUDIR RCCNEWDIR RCCBKUPDIR RCC_SECURE_MSG RCCNETSVPRIOCNTL SHLIB_PATH LD_LIBRARY_PATH FLXCPUMODEL RCCSYSLOG PATH RCCPNETS RCCANETS RCCBNETS RCCBANETS RCC_MESSAGE_NON_REVERTIVE RCCLCM_RCMOD
    RCCLCM_RCVP1 RCCLCM_INTVL RCCLCM_WAITTIME RCCGCM_VCETMOUT RCC_VCE_UP_TMOUT RCC_VCE_DOWN_TMOUT RCC_LOCKVDISK RCC_LOCKWDI RCC_LOCKSMON RCC_TEARDOWNDELAY RCCNET_AUTORST_TIME AVCVM_PRI_MACH_TMOUT
    AVCVM_PRI_AVCM_TMOUT PINGCOUNT SWD_TRACESIZE HITT_STARTUPFILE HITT_COUNTFILE HITT_RESTART_INTERVAL HITT_RESTART_COUNT RCC_RECOVER_UNHEALTHY RCC_USE_ECHO_BROADCAST RCC_PROBE_TARGET_LIST_FILE
    RCC_RMTCMD_TMOUT RCCARP_UPDATE_TIME APPLBASEDIR APPLNEWDIR APPLBKUPDIR APPLFAILDIR CLUSTERMODE RCC_SET_MACH_INIT RCCANET_FAILED_REBOOT SOFTWARE_WATCHDOG TEST_ENVIRONMENT SWD_CONSOLESIZE LM_LICENSE_FILE
    EORBHOME EORBENV EORBTMPDIR RUN runapp RCCANET_CHECK_NETERR RCCSYSLOGSIZE RCCSYSLOGNUMBER1 RCCNET_DO_NOT_REBOOT RCC_USE_FIXED_LANS RCC_IMMEDIATE_REBOOT_ON_SYSVM_FAIL RCC_GCM_CLEANUP_DELAY SIR_TIMER_DELAY
    HAL_bas HOME  MALLOC_CHECK_  RUNPATH  SK_LIB_DIR  SK_NUM_RETRIES_TO_LLC  SK_SOCKET_VALIDATE_WAIT  SK_SOCKET_VALIDATE_DELAY  SK_DOWNLOAD_METHOD  SK_LLC_HOST SK_RLLC_HOST  SK_LOG_DIR  LOG_VERBOSITY
    SOFTSWITCH_BASE  SOFTSWITCH_HOME  MANTRA_HOME  LLC_PATH  EPIX_HOME  EXS_SSHOST  SOFTSWITCH_LIB  CLASSPATH  SMENV_PATH  LSSAPISERVER_LOG_CONFIG_PATH  LSSAPISERVER_OAM_CONFIG_PATH
    LSSAPISERVER_OAMSERVER_CONFIG_PATH  SHELL  MSOFTLM_HOST SK_OMAP_ENABLED  SK_RCC_ENABLED  SK_APP_DISABLED_TIMEOUT  SK_APP_RECONNECT_TIMEOUT  CDR_DEBUG  CDR_DIRECTORY  GDI_DIR GDI_SW_DIR GDI_RECORD_SIZE
    GDI_BLOCK_SIZE GDI_MINI_RECS GDI_MINI_IN_WHOLE TRACE_DIR SR_TRAP_TEST_PORT SR_MGR_CONF_DIR SR_AGT_CONF_DIR EXS_PATH GUIDATA_DIR PMCOLLECTOR_DIR LOW_IDLE_VALUE LOG_CFG_FILE LOG_DEV  LOG_CLIENT_PATH
    LOG_SERVER_IP OLDLOGS RCC_USE_RAILS OPENHPI_READ_TIMEOUT OPENHPI_USE_KEEPALIVE OPENHPI_DAEMON_PORT OPENHPI_DAEMON_HOST REM_LOCALHOST SYSCONF_DIR STATCONF_DIR HOSTDIR_PATH APPLI_PATH NAMING_DATA_PATH
    NAMING_TYPE_PATH BYPASS_NAMING HOSTLAYOUT APPLILAYOUT NAMING_DATA_LAYOUT NAMING_TYPE_LAYOUT HOST_DATA_HOST_HARDWARE_SHELF HOST_DATA_HOST_HARDWARE_CARD HOST_DATA_HOST_HARDWARE_HOSTN
    HOST_DATA_SERVICE_TYPE_NAME HOST_DATA_SERVICE_TYPE_NO HOST_DATA_POOL_NUMBER HOST_DATA_POOL_MEMBER HOST_DATA_FIXED_INTERNAL_SERVICE_IP_ADDRESS IPDATA_INIT SU_LOG_FILE MY_LOG_FILE MY_USER KSH_VSN
    SERVICEINFO_PATH PKGDETAILS_PATH SVINFLAYOUT PKGDETAILSLAYOUT ZIPINFO OS_NAME OS_PLATFORM OS_DISTRIBUTION PRODUCT_LEVEL JAVA_HOME IBM_HEAPDUMPDIR IBM_JAVACOREDIR IBM_COREDIR JITC_PROCESSOR_TYPE
    IBM_JAVA_OPTIONS IBM_HEAPDUMP JAVA_COMPILER DB_CLASSPATH WEBNMS_DB_NAME PERSISTANCE_DIRECTORY MI_OAMTYPE SERVICE_DATA_SERVICE_POOL SERVICE_DATA_POOL_SIZE SERVICE_DATA_ACTIVE_NUMBER
    SERVICE_DATA_STANDBY_NUMBER NAME LESS MIBS MANPATH PERL5LIB MIBDIRS REMOTE_PASSWORD OPENSSL_CONF BLZ_DBPATH HOST_DATA_HOST_HARDWARE   HOST_DATA_HOST_CARDTYPE   HOST_DATA_HOST_FUNCTIONTYPE
    HOST_DATA_HOST_MNEMONIC   HOST_DATA_HOST_BSPCLASS   HOST_DATA_HOST_BOOTTYPE   HOST_DATA_HOST_LSN0NAME   HOST_DATA_HOST_LSN0ADDR   HOST_DATA_HOST_LSN1NAME   HOST_DATA_HOST_LSN1ADDR
    HOST_DATA_HOST_HOSTNAME   HOST_DATA_HOST_HOSTADDR   HOST_DATA_HOST_NAME   HOST_DATA_HOST_IPADDRESS   HOST_DATA_HOST_DHCP0NAME   HOST_DATA_HOST_DHCP0ADDR   HOST_DATA_HOST_DHCP1NAME
    HOST_DATA_HOST_DHCP1ADDR   HOST_DATA_SERVICE_POOL   HOST_DATA_SERVICE_POOLS THIS   CURR_CMD   WORKDIR   LOCAL_ISQL_SCRIPT   REMOTE_ISQL_SCRIPT   COM_WRK   SHLFSLT_LST   POOLMEM_LST   POOLFLO_LST
    NORM_COND   SU_COND   NEWLOAD_SU_COND   ACTIVE_LOAD   SYNCDD_LOAD   PRE_SYNCDD_LOAD   ALL_EXPN_pool_members   ALL_EXPN_hosts   ALL_EXPN_floaters   LI_EXPN   MC_EXPN   SV_EXPN   STS_EXPN   FLOATER_TBL
    HOST_TBL   POOLMEM_TBL   SU_LEVEL_DONTCARE   SU_ISQLDIR   LOCAL_ISQL_FILE   REMOTE_ISQL_FILE   CTRLTYPE   HWTYPE   SHLFSLT_LIST_ALL   POOLMEM_LST_ALL   POOLFLO_LST_ALL   SHLFSLT_LST_A   POOLMEM_LST_A
    POOLFLO_LST_A   SHLFSLT_LST_B   POOLMEM_LST_B   POOLFLO_LST_B   ALL_EXPN   VERS_MI   VERS_CNFG_A"

Runas and Command-specific defaults for lss:
    Defaults!/usr/bin/less /export/home/lss/logs/imsli-asn*, /usr/bin/less /export/home/lss/logs/li.log*, /usr/bin/less /export/home/lss/logs/imsli-debug*, /usr/bin/rm /export/home/lss/logs/imsli-asn*,
    /usr/bin/rm /export/home/lss/logs/li.log*, /usr/bin/rm /export/home/lss/logs/imsli-debug* noexec

User lss may run the following commands on sbclcm-oam-a:
    (root) NOPASSWD: /opt/LSS/sbin/upd_powerstate, /opt/LSS/sbin/lss_adm, /opt/LSS/bin/lss_adm, /opt/LSS/sbin/plex_adm, /opt/LSS/sbin/lng_adm, /opt/LSS/sbin/mi_adm, /opt/LSS/bin/mi_adm,
        /opt/LSS/sbin/startmi, /opt/LSS/sbin/stopmi, /opt/LSS/sbin/midbinit, /opt/LSS/sbin/StandbyAgent, /opt/RCC/bin/rcctestcfg, /opt/RCC/bin/RCCmaint, /opt/RCC/bin/RCCmachoffline,
        /opt/RCC/bin/RCCmachonline, /opt/RCC/bin/RCCvmOffline, /opt/RCC/bin/RCCvmOnline, /opt/RCC/bin/RCCvcOffline, /opt/RCC/bin/RCCvcOnline, /opt/RCC/bin/RCCvcswitch, /opt/RCC/bin/RCCcstat,
        /opt/RCC/bin/RCCstatus, /opt/RCC/bin/RCCping, /opt/RCC/bin/RCC_prnt_clent, /opt/RCC/bin/RCC_prnt_clustinfo, /opt/RCC/bin/RCC_prnt_hwconfig, /opt/RCC/bin/RCC_prnt_machinfo, /opt/LSS/sbin/LSSbackup,
        /opt/LU3P/bin/mysqladmin, /opt/LSS/sbin/alarm_cli, /opt/LSS/sbin/clisendalarms, /opt/LSS/sbin/guidbx, /export/home/lss/bin/chffowner, /export/home/lss/bin/chcoreowner
    (root) NOEXEC: NOPASSWD: /opt/LU3P/bin/mysql
    (root) NOPASSWD: /opt/LSS/sbin/getIdForLicense, /opt/LU3P/bin/openssl dhparam -out * -5 512, /opt/LU3P/bin/openssl genrsa -out * 2048, /opt/LU3P/bin/openssl req -new -x509 -sha256 -days [0-9]* -key *
        -out * -subj * -config *, /opt/LU3P/bin/openssl req -new -sha256 -key * -out * -subj * -config *, /opt/LU3P/bin/openssl req -new -config * -key * -out * -x509 -days [0-9]*, /opt/LU3P/bin/openssl req
        -new -days [0-9]* -subj * -key * -out *, /opt/LU3P/bin/openssl req -config * -new -key * -out *, /opt/LU3P/bin/openssl req -config * -nodes -new -x509 -days [0-9]* -sha256 -keyout * -out *,
        /opt/LU3P/bin/openssl req -x509 -batch -newkey rsa\:[0-9]* -days [0-9]* -keyout * -out * -config *, /opt/LU3P/bin/openssl ca -batch -config * -days [0-9]* -key * -out * -infiles *,
        /opt/LU3P/bin/openssl enc -aes-256-cbc -a -pass *, /opt/LU3P/bin/openssl enc -aes-256-cbc -md md5 -a -pass *, /opt/LU3P/bin/openssl dgst -sha1 -binary, /opt/LU3P/bin/openssl x509 -text -noout,
        /opt/LU3P/bin/openssl verify -CAfile *, /opt/LU3P/bin/openssl genrsa -des3 -out * [0-9]*, /opt/LU3P/bin/openssl genrsa -rand * -out * [0-9]*, /opt/LU3P/bin/openssl genrsa -out * [0-9]*,
        /opt/LU3P/bin/openssl ecparam -genkey -name prime256v1 -out *, /opt/LU3P/bin/openssl dsaparam -genkey -out * [0-9]*, /opt/LU3P/bin/openssl dsaparam -rand * -out * [0-9]*, /opt/LU3P/bin/openssl
        dsaparam -out * [0-9]*, /opt/LU3P/bin/openssl gendsa -rand * -out *, /opt/LU3P/bin/openssl gendsa -out *, /opt/LU3P/bin/openssl rsautl -encrypt -pubin -inkey * -out *, /opt/LU3P/bin/openssl genpkey
        -algorithm RSA -out * -pkeyopt rsa_keygen_bits\:2048, /opt/LSS/sbin/MIcmd, /opt/LSS/bin/MIcmd, /opt/LSS/bin/FScmd, /opt/cso/server/bin/chg_pass, /opt/LSS/sbin/lcp_status, /opt/RCC/bin/RCCmachoffline,
        /opt/RCC/bin/RCCmachonline, /opt/RCC/bin/RCCmachpanic, /opt/RCC/bin/RCCmaint, /opt/RCC/bin/RCCmsglevel, /opt/RCC/bin/RCCnodereset, /opt/RCC/bin/RCCstateChange, /opt/RCC/bin/RCCvcOffline,
        /opt/RCC/bin/RCCvcOnline, /opt/RCC/bin/RCCvcvmswitch, /opt/RCC/bin/RCCvmOffline, /opt/RCC/bin/RCCvmOnline, /opt/RCC/bin/configRCC, /opt/RCC/bin/RCCinhibitpsa, /opt/RCC/bin/RCCmachoffline,
        /opt/RCC/bin/RCCmachonline, /opt/RCC/bin/RCCmachpanic, /opt/RCC/bin/RCCmaint, /opt/RCC/bin/RCCnodereset, /opt/RCC/bin/rccpostinstall, /opt/RCC/bin/rccpreinstall, /opt/RCC/bin/RCCstateChange,
        /opt/RCC/bin/RCCvcOffline, /opt/RCC/bin/RCCvcOnline, /opt/RCC/bin/RCCvcvmswitch, /opt/RCC/bin/RCCvmOffline, /opt/RCC/bin/RCCvmOnline, /opt/RCC/bin/RCCmachoffline, /opt/RCC/bin/RCCmachonline,
        /opt/RCC/bin/RCCmachpanic, /opt/RCC/bin/RCCmaint, /opt/RCC/bin/RCCnodereset, /opt/RCC/bin/RCCstateChange, /opt/RCC/bin/RCCvcOffline, /opt/RCC/bin/RCCvcOnline, /opt/RCC/bin/RCCvcvmswitch,
        /opt/RCC/bin/RCCvmOffline, /opt/RCC/bin/RCCvmOnline, /opt/RCC/bin/chksumload, /opt/RCC/bin/RCC_chgclent_alarm, /opt/RCC/bin/RCC_chgclent_appl, /opt/RCC/bin/RCC_chgclent_crmpname,
        /opt/RCC/bin/RCC_chgclent_crmppath, /opt/RCC/bin/RCC_chgclent_crmptimers, /opt/RCC/bin/RCC_chgclent_links, /opt/RCC/bin/RCC_chgclent_machine, /opt/RCC/bin/RCC_chgclent_port,
        /opt/RCC/bin/RCC_chgclent_resetcntinterval, /opt/RCC/bin/RCC_chgclent_restartcnt, /opt/RCC/bin/RCC_chgclent_seqlev, /opt/RCC/bin/RCC_chgclent_state, /opt/RCC/bin/RCC_chgclent_vce,
        /opt/RCC/bin/RCC_chgclent_vmsustate, /opt/RCC/bin/RCC_chgclent_vmversion, /opt/RCC/bin/RCC_chgcluster_alarm, /opt/RCC/bin/RCC_chgcluster_appl, /opt/RCC/bin/RCC_chgmach_alarm,
        /opt/RCC/bin/RCC_chgmach_allstates, /opt/RCC/bin/RCC_chgmach_aparam, /opt/RCC/bin/RCC_chgmach_appl, /opt/RCC/bin/RCC_chgmach_asustate, /opt/RCC/bin/RCC_chgmach_inhibit,
        /opt/RCC/bin/RCC_chgmach_iparam, /opt/RCC/bin/RCC_chgmach_isustate, /opt/RCC/bin/RCC_chgmach_nextstate, /opt/RCC/bin/RCC_chgmach_state, /opt/RCC/bin/RCC_chgmach_ttimers, /opt/RCC/bin/RCCaddclent,
        /opt/RCC/bin/RCCaddcluster, /opt/RCC/bin/RCCaddmachine, /opt/RCC/bin/RCCadmin, /opt/RCC/bin/RCCdelclent, /opt/RCC/bin/RCCdelcluster, /opt/RCC/bin/RCCdelmachine, /opt/RCC/bin/RCCdgrowCluster,
        /opt/RCC/bin/RCCdgrowNode, /opt/RCC/bin/RCCdgrowService, /opt/RCC/bin/RCCdgrowVC, /opt/RCC/bin/RCCdgrowVM, /opt/RCC/bin/RCCdisablerelmeas, /opt/RCC/bin/RCCenablerelmeas, /opt/RCC/bin/RCCgrowCluster,
        /opt/RCC/bin/RCCgrowNode, /opt/RCC/bin/RCCgrowService, /opt/RCC/bin/RCCgrowVC, /opt/RCC/bin/RCCgrowVM, /opt/RCC/bin/RCCinstallmeasurementfile, /opt/RCC/bin/RCCmigration,
        /opt/RCC/bin/RCCresetrelmeasdata, /opt/RCC/bin/RCCsnhbCLI, /opt/RCC/bin/RCCstartvm, /opt/RCC/bin/RCCstopvm, /opt/LSS/sbin/upd_powerstate, /opt/LSS/sbin/lss_adm, /opt/LSS/bin/lss_adm,
        /opt/LSS/sbin/plex_adm, /opt/LSS/sbin/lng_adm, /opt/LSS/sbin/mi_adm, /opt/LSS/bin/mi_adm, /opt/LSS/sbin/startmi, /opt/LSS/sbin/stopmi, /opt/LSS/sbin/midbinit, /opt/LSS/sbin/StandbyAgent,
        /opt/RCC/bin/rcctestcfg, /opt/RCC/bin/RCCmaint, /opt/RCC/bin/RCCmachoffline, /opt/RCC/bin/RCCmachonline, /opt/RCC/bin/RCCvmOffline, /opt/RCC/bin/RCCvmOnline, /opt/RCC/bin/RCCvcOffline,
        /opt/RCC/bin/RCCvcOnline, /opt/RCC/bin/RCCvcswitch, /opt/RCC/bin/RCCcstat, /opt/RCC/bin/RCCstatus, /opt/RCC/bin/RCCping, /opt/RCC/bin/RCC_prnt_clent, /opt/RCC/bin/RCC_prnt_clustinfo,
        /opt/RCC/bin/RCC_prnt_hwconfig, /opt/RCC/bin/RCC_prnt_machinfo, /opt/LSS/sbin/LSSbackup, /opt/LU3P/bin/mysqladmin, /opt/LSS/sbin/alarm_cli, /opt/LSS/sbin/clisendalarms, /opt/LSS/sbin/guidbx,
        /export/home/lss/bin/chffowner, /export/home/lss/bin/chcoreowner, /opt/LSS/sbin/vortex_editor, /opt/LSS/bin/xml2cfg, /export/home/lss/config/xlsprov/xlsprov,
        /export/home/lss/config/xlsprov/xls2xml.py, /opt/LSS/sbin/health, /opt/LSS/sbin/sbc_health, /opt/LSS/sbin/get_logs, /opt/LSS/sbin/get_version, /opt/LSS/sbin/rcc_srv_state,
        /opt/LSS/sbin/rem_srv_state, /opt/LSS/sbin/oam_setup, /opt/LSS/share/rmt/scripts/RMT_BKUPEXPORT, /opt/LSS/share/rmt/scripts/RMT_IMPORTBKUP, /opt/LSS/share/rmt/scripts/RMT_SOFTWARE_INVENTORY,
        /opt/LSS/share/rmt/scripts/RMT_INSTALL_AGENT, /opt/LSS/share/rmt/scripts/RMT_DOWNLOAD, /opt/LSS/share/rmt/scripts/RMT_SU_VERIFY, /opt/LSS/share/rmt/scripts/RMT_SU_PREPARE,
        /opt/LSS/share/rmt/scripts/RMT_SU_PRE_ACTIVATE, /opt/LSS/share/rmt/scripts/RMT_SU_ACTIVATE, /opt/LSS/share/rmt/scripts/RMT_SU_POST_ACTIVATE, /opt/LSS/share/rmt/scripts/RMT_SU_COMMIT,
        /opt/LSS/share/rmt/scripts/RMT_SU_BACKOUT, /opt/LSS/share/rmt/scripts/RMT_SU_ROLLBACK, /opt/LSS/share/rmt/scripts/RMT_SU_MGC_PREPARE, /opt/LSS/share/rmt/scripts/RMT_SU_MGC_ACTIVATE,
        /opt/LSS/share/rmt/scripts/RMT_SU_MGC_COMMIT, /opt/LSS/share/rmt/scripts/RMT_SU_MGC_BACKOUT, /opt/LSS/share/rmt/scripts/RMT_PAUSE, /var/opt/tmp/update/opt/LSS/sbin/get_logs,
        /var/opt/tmp/update/opt/LSS/sbin/get_version, /var/opt/tmp/update/opt/LSS/sbin/rcc_srv_state, /var/opt/tmp/update/opt/LSS/sbin/rem_srv_state, /var/opt/tmp/update/opt/LSS/sbin/health,
        /var/opt/tmp/update/opt/LSS/sbin/oam_setup, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SOFTWARE_INVENTORY, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_INSTALL_AGENT,
        /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_DOWNLOAD, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_VERIFY, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_PREPARE,
        /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_PRE_ACTIVATE, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_ACTIVATE, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_POST_ACTIVATE,
        /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_COMMIT, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_BACKOUT, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_ROLLBACK,
        /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_MGC_PREPARE, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_MGC_ACTIVATE, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_MGC_COMMIT,
        /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_SU_MGC_BACKOUT, /var/opt/tmp/update/opt/LSS/share/rmt/scripts/RMT_PAUSE, /opt/LSS/sbin/sbc_logs, VLR_LCP_CMDS, /opt/LSS/sbin/INVgen,
        /opt/LSS/sbin/INVrun, /opt/LSS/bin/pmScheduleCli, /opt/LSS/sbin/SAinit, /opt/LSS/sbin/bkup_adm, /opt/LSS/bin/bkup_adm, /opt/LSS/sbin/lcp_adm, /opt/LSS/bin/lcp_adm, /opt/LSS/sbin/enum_adm,
        /opt/LSS/bin/enum_adm, /opt/LSS/sbin/sac_adm, /opt/LSS/sbin/connectTL1, /opt/LSS/sbin/miconfig, /opt/LSS/sbin/mi_audit, /opt/LSS/sbin/mi_maint, /opt/LSS/sbin/mi_testalarm, /opt/LSS/sbin/brevity,
        /opt/LSS/sbin/discovery_cli, /opt/LSS/sbin/sync_alarm_cli, /opt/LSS/sbin/calltrace, /opt/LSS/sbin/dnsconf_adm, /opt/LSS/sbin/dns_adm, /opt/LSS/bin/dns_adm, /opt/LSS/sbin/tz_adm, /opt/LSS/bin/tz_adm,
        /opt/LSS/sbin/kernel_adm, /opt/LSS/share/basecfg/fi/bin/lcm_util, /opt/LSS/sbin/esc_adm
    (lss) NOPASSWD: /opt/LSS/share/sudo/
    (root) NOEXEC: NOPASSWD: /opt/LU3P/bin/mysql
    (lss) NOPASSWD: CDR_LCP_CMDS
    (root) NOPASSWD: /opt/LSS/sbin/lcp_status, /opt/cso/server/bin/chg_pass
    (root) NOPASSWD: /opt/cso/server/bin/chg_pass, /opt/LSS/sbin/lcp_status, /opt/LSS/sbin/dumpcars, /opt/LSS/sbin/calltrace, /opt/LSS/bin/MIvmstate
    (lss) NOPASSWD: /opt/LSS/share/sudo/dpsrch, /opt/LSS/share/sudo/adns_cli, /opt/LSS/share/sudo/scrcli, /opt/LSS/share/sudo/ims_cli
    (root) NOPASSWD: /opt/LSS/bin/ACLCheckBin
    (root) NOPASSWD: /opt/LSS/sbin/pmhealth, /opt/LSS/sbin/INVgen, /opt/LSS/sbin/INVrun, /opt/LSS/sbin/lcp_status, /opt/cso/server/bin/chg_pass
    (root) NOPASSWD: /opt/LSS/sbin/lcp_adm, /opt/LSS/sbin/lss_adm, /opt/LSS/sbin/mi_adm, /opt/LSS/sbin/bkup_adm
    (root) NOPASSWD: /opt/LSS/bin/ACLCheckBin
    (root) NOPASSWD: /opt/LSS/sbin/taillog, /opt/LSS/sbin/cplog`
