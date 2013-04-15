/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * [WIFI] Enable Wi-Fi Support, Please reference [PROJECT]/device/$(OEM)/$(TARGET_DEVICE)/BoardConfig.mk
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>

#include "SoftapController.h"


//#define CONFIG_DAEMON_CMD_WITH_PARA
#define CONFIG_WLAN_RTK_WIFI_HOSTAPD
#ifdef CONFIG_WLAN_RTK_WIFI_HOSTAPD     /* [WIFI] Wi-Fi Support ++ */

//#include <ctype.h>
//#include "private/android_filesystem_config.h"
//#include "cutils/properties.h"
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#endif

//#include <sys/_system_properties.h>
//#include <libhostapd_client/wpa_ctrl.h>


extern "C" int wifi_load_ap_driver();
extern "C" int wifi_unload_driver();

extern "C" int set_hostapd_config_file(int argc, char *argv[]);
extern "C" int wifi_start_hostapd();
extern "C" int wifi_stop_hostapd();
extern "C" int wifi_connect_to_hostapd();
extern "C" void wifi_close_hostapd_connection();
extern "C" int wifi_load_profile(int started);

#endif  /* CONFIG_WLAN_RTK_WIFI_HOSTAPD [WIFI] Wi-Fi Support -- */


SoftapController::SoftapController() {
	mPid = 0;
	mSock = socket(AF_INET, SOCK_DGRAM, 0);
	if (mSock < 0)
		LOGE("Failed to open socket");
	
	memset(mIface, 0, sizeof(mIface));
}

SoftapController::~SoftapController() {
	if (mSock >= 0)
		close(mSock);
}

int SoftapController::getPrivFuncNum(char *iface, const char *fname) {
    struct iwreq wrq;
    struct iw_priv_args *priv_ptr;
    int i, ret;

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.pointer = mBuf;
    wrq.u.data.length = sizeof(mBuf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    if ((ret = ioctl(mSock, SIOCGIWPRIV, &wrq)) < 0) {
        LOGE("SIOCGIPRIV failed: %d", ret);
        return ret;
    }
    priv_ptr = (struct iw_priv_args *)wrq.u.data.pointer;
    for(i=0;(i < wrq.u.data.length);i++) {
        if (strcmp(priv_ptr[i].name, fname) == 0)
            return priv_ptr[i].cmd;
    }
    return -1;
}

int SoftapController::startDriver(char *iface) {
	int ret = 0;
	LOGD("SoftapController::startDriver");
	if (mSock < 0) {
		LOGE("Softap driver start - failed to open socket");
		return -1;
	}
	if (!iface || (iface[0] == '\0')) {
		LOGD("Softap driver start - wrong interface");
		iface = mIface;
	}

	ret = wifi_load_ap_driver();

	LOGD("Softap driver start: %d", ret);
	
	return ret;
}

int SoftapController::stopDriver(char *iface) {
	int ret = 0;
	LOGE("SoftapController::stopDriver");

	if (mSock < 0) {
		LOGE("Softap driver stop - failed to open socket");
		return -1;
	}
	if (!iface || (iface[0] == '\0')) {
		LOGD("Softap driver stop - wrong interface");
		iface = mIface;
	}

	//Is this needed??
	//ret = wifi_unload_driver();

	LOGD("Softap driver stop: %d", ret);
	return ret;
}

int SoftapController::startSoftap() {
	struct iwreq wrq;
	pid_t pid = 1;
	int fnum, ret = 0;

	LOGD("SoftapController::startSoftap");

	if (mPid) {
		LOGE("Softap already started");
		return 0;
	}

	if (mSock < 0) {
		LOGE("Softap startap - failed to open socket");
		return -1;
	}

	if ((ret = wifi_start_hostapd()) < 0) {
		LOGE("Softap startap - starting hostapd fails");
		return -1;
	}
       
	if ((ret = wifi_connect_to_hostapd()) < 0) {
		LOGE("Softap startap - connect to hostapd fails");
		return -1;
	}

	if ((ret = wifi_load_profile(1)) < 0) {
		LOGE("Softap startap - load new configuration fails");
		return -1;
	}

	if (ret) {
		LOGE("Softap startap - failed: %d", ret);
	}
	else {
		mPid = pid;
		LOGD("Softap startap - Ok");
		//usleep(AP_BSS_START_DELAY);
	}
	return ret;

}

int SoftapController::stopSoftap() {
	struct iwreq wrq;
	int fnum, ret;

	LOGD("softapcontroller->stopSoftap");

	if (mPid == 0) {
		LOGE("Softap already stopped");
		return 0;
	}
	if (mSock < 0) {
		LOGE("Softap stopap - failed to open socket");
		return -1;
	}
	
	wifi_close_hostapd_connection();
	ret = wifi_stop_hostapd();

	mPid = 0;
	LOGD("Softap service stopped: %d", ret);
	//usleep(AP_BSS_STOP_DELAY);
	
	return ret;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

int SoftapController::addParam(int pos, const char *cmd, const char *arg)
{
    if (pos < 0)
        return pos;
    if ((unsigned)(pos + strlen(cmd) + strlen(arg) + 1) >= sizeof(mBuf)) {
        LOGE("Command line is too big");
        return -1;
    }
    pos += sprintf(&mBuf[pos], "%s=%s,", cmd, arg);
    return pos;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
	unsigned char psk[SHA256_DIGEST_LENGTH];
	char psk_str[2*SHA256_DIGEST_LENGTH+1];
	struct iwreq wrq;
	int fnum, ret, i = 0;
	char *ssid;

	if (mSock < 0) {
		LOGE("Softap set - failed to open socket");
		return -1;
	}
	if (argc < 4) {
		LOGE("Softap set - missing arguments");
		return -1;
	}
	
	if ((ret = set_hostapd_config_file(argc, argv)) < 0) {
		LOGE("Softap set - set_hostapd_config_file fails");
		return -1;
	}

	if ((ret = wifi_load_profile(isSoftapStarted()?1:0)) < 0) {
		LOGE("Softap set - load new configuration fails");
		return -1;
	}    

	if (ret) {
		LOGE("Softap set - failed: %d", ret);
	} else {
		LOGD("Softap set - Ok");
		//usleep(AP_SET_CFG_DELAY);
	}
	return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
	struct iwreq wrq;
	int fnum, ret, i = 0;
	char *iface;

	if (mSock < 0) {
		LOGE("Softap fwrealod - failed to open socket");
		return -1;
	}
	if (argc < 4) {
		LOGE("Softap fwreload - missing arguments");
		return -1;
	}
	
	ret = 0;

	if (ret) {
		LOGE("Softap fwReload - failed: %d", ret);
	}
	else {
		LOGD("Softap fwReload - Ok");
	}
	return ret;
}
