/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "error.h"
#include "uinput.h"
#include "adapter.h"
#include "../src/device.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "btio.h"
#include "dbus-common.h"

#define AVCTP_PSM 23
#define AVCTP_BROWSING_PSM 0x001B

/* Message types */
#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		1

/* Packet types */
#define AVCTP_PACKET_SINGLE	0
#define AVCTP_PACKET_START	1
#define AVCTP_PACKET_CONTINUE	2
#define AVCTP_PACKET_END	3

/* ctype entries */
#define CTYPE_CONTROL		0x0
#define CTYPE_STATUS		0x1
#define CTYPE_NOT_IMPLEMENTED	0x8
#define CTYPE_ACCEPTED		0x9
#define CTYPE_REJECTED		0xA
#define CTYPE_STABLE		0xC
#define CTYPE_NOTIFY		0x3
#define CTYPE_INTERIM		0xF
#define CTYPE_CHANGED		0xD

/* opcodes */
#define OP_UNITINFO		0x30
#define OP_SUBUNITINFO		0x31
#define OP_PASSTHROUGH		0x7c
#define OP_VENDORDEPENDENT	0x0

/* subunits of interest */
#define SUBUNIT_PANEL		0x09

/* operands in passthrough commands */
#define VOL_UP_OP		0x41
#define VOL_DOWN_OP		0x42
#define MUTE_OP			0x43
#define PLAY_OP			0x44
#define STOP_OP			0x45
#define PAUSE_OP		0x46
#define RECORD_OP		0x47
#define REWIND_OP		0x48
#define FAST_FORWARD_OP		0x49
#define EJECT_OP		0x4a
#define FORWARD_OP		0x4b
#define BACKWARD_OP		0x4c

#define QUIRK_NO_RELEASE	1 << 0
#define QUIRK_NO_CAPABILITIES	1 << 1
#define QUIRK_NO_METADATA	1 << 2
#define QUIRK_NO_NOTIFICATIONS	1 << 3

/* BT SIG IDs */
#define SIG_ID_BTSIG		0X1958

/* AVRCP1.3 PDU IDs */
#define PDU_GET_CAPABILITY_ID		0x10
#define PDU_LIST_PLAYER_APP_SETT_ATTR	0x11
#define PDU_GET_ELEMENT_ATTRIBUTES	0x20
#define PDU_RGR_NOTIFICATION_ID		0X31
#define PDU_REQ_CONTINUE_RSP_ID		0X40
#define PDU_ABORT_CONTINUE_RSP_ID	0X41
#define PDU_GET_PLAY_STATUS_ID		0x30

/* AVRCP1.3 Capability IDs */
#define CAP_COMPANY_ID		0X2
#define CAP_EVENTS_SUPPORTED_ID	0X3

/* AVRCP1.3 Supported Events */
#define EVENT_PLAYBACK_STATUS_CHANGED	0x1
#define EVENT_TRACK_CHANGED		0x2
#define EVENT_AVAILABLE_PLAYERS_CHANGED	0xa
#define EVENT_ADDRESSED_PLAYER_CHANGED	0xb

/* AVRCP1.3 Error/Staus Codes */
#define ERROR_INVALID_PDU	0x00
#define ERROR_INVALID_PARAMETER	0x01
#define ERROR_PARAM_NOT_FOUND	0X02
#define ERROR_INTERNAL		0X03
#define STATUS_OP_COMPLETED	0X04
#define STATUS_UID_CHANGED	0X05
#define ERROR_INVALID_DIRECTION	0X07
#define ERROR_NO_DIRECTORY	0X08
#define ERROR_UID_NOT_EXIST	0X09

/* AVRCP1.3 MetaData Attributes ID */
#define METADATA_TITLE		0X1
#define METADATA_ARTIST		0X2
#define METADATA_ALBUM		0X3
#define METADATA_MEDIA_NUMBER	0X4
#define METADATA_TOTAL_MEDIA	0X5
#define METADATA_GENRE		0X6
#define METADATA_PLAYING_TIME	0X7

#define METADATA_SUPPORTED_MASK	0x5F
#define METADATA_MAX_FIELDS	6
#define METADATA_MAX_STRING_LEN	150
#define METADATA_MAX_NUMBER_LEN	40
#define DEFAULT_METADATA_STRING	"Unknown"
#define DEFAULT_METADATA_NUMBER	"1234567890"
#define AVRCP_MAX_PKT_SIZE	512

/* AVRCP1.3 Character set */
#define CHARACTER_SET_UTF8	0X6A

/* AVRCP1.3 Playback status */
#define STATUS_STOPPED	0X00
#define STATUS_PLAYING	0X01
#define STATUS_PAUSED	0X02
#define STATUS_FWD_SEEK	0X03
#define STATUS_REV_SEEK	0X04
#define STATUS_ERROR	0XFF

#define IEEEID_BTSIG 0x001958

static DBusConnection *connection = NULL;
static gchar *input_device_name = NULL;
static GSList *servers = NULL;

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));

struct avrcp_header {
	struct avctp_header avctp;
	uint8_t code:4;
	uint8_t _hdr0:4;
	uint8_t subunit_id:3;
	uint8_t subunit_type:5;
	uint8_t opcode;
} __attribute__ ((packed));

struct avrcp_params {
	struct avrcp_header avrcp;
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t packet_type:2;
	uint8_t reserved:6;
	uint16_t param_len;
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));

struct avrcp_header {
	struct avctp_header avctp;
	uint8_t _hdr0:4;
	uint8_t code:4;
	uint8_t subunit_type:5;
	uint8_t subunit_id:3;
	uint8_t opcode;
} __attribute__ ((packed));

struct avrcp_params {
	struct avrcp_header avrcp;
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t reserved:6;
	uint8_t packet_type:2;
	uint16_t param_len;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

struct avrcp_caps {
	struct avrcp_params params;
	uint8_t capability_id;
} __attribute__ ((packed));

struct avrcp_cmd_get_elem_attributes_req {
	struct avrcp_params params;
	uint64_t identifier;
	uint8_t count;
	uint32_t attributes[0];
} __attribute__ ((packed));

struct meta_data_field {
	uint32_t att_id;
	uint16_t char_set_id;
	uint16_t att_len;
	char val[0];
} __attribute__ ((packed));

struct avrcp_play_status {
	struct avrcp_params params;
	uint32_t song_len;
	uint32_t song_pos;
	uint8_t play_status;
} __attribute__ ((packed));

struct avrcp_event {
	struct avrcp_caps caps;
	union {
		struct {
			uint32_t track_high;
			uint32_t track_low;
		} track_changed;
		struct {
			uint8_t status;
		} playback_status_changed;
		struct player_changed {
			uint16_t player_id;
			uint16_t uid_counter;
		} player_changed;
	} event;
} __attribute__ ((packed));

struct avctp_state_callback {
	avctp_state_cb cb;
	void *user_data;
	unsigned int id;
};

struct avctp_server {
	bdaddr_t src;
	GIOChannel *io;
	uint32_t tg_record_id;
#ifndef ANDROID
	uint32_t ct_record_id;
#endif
};

struct meta_data {
	gchar *title;
	gchar *artist;
	gchar *album;
	gchar *media_number;
	gchar *total_media_count;
	gchar *playing_time;
	gchar *remaining_mdata;
	int remaining_mdata_len;
	uint8_t trans_id_event_track;
	uint8_t trans_id_event_playback;
	uint8_t trans_id_event_addressed_player;
	uint8_t trans_id_event_available_player;
	uint8_t trans_id_get_play_status;
	gboolean reg_track_changed;
	gboolean reg_playback_status;
	gboolean reg_addressed_player;
	gboolean reg_available_player;
	gboolean req_get_play_status;
	uint8_t current_play_status;
};

struct control {
	struct audio_device *dev;

	avctp_state_t state;

	int uinput;

	GIOChannel *io;
	guint io_id;

	uint16_t mtu;

	gboolean target;

	uint8_t key_quirks[256];
	uint8_t avrcp_quirks;

	gboolean ignore_pause;
	struct meta_data *mdata;
};

static struct {
	const char *name;
	uint8_t avrcp;
	uint16_t uinput;
} key_map[] = {
	{ "PLAY",		PLAY_OP,		KEY_PLAYCD },
	{ "STOP",		STOP_OP,		KEY_STOPCD },
	{ "PAUSE",		PAUSE_OP,		KEY_PAUSECD },
	{ "FORWARD",		FORWARD_OP,		KEY_NEXTSONG },
	{ "BACKWARD",		BACKWARD_OP,		KEY_PREVIOUSSONG },
	{ "REWIND",		REWIND_OP,		KEY_REWIND },
	{ "FAST FORWARD",	FAST_FORWARD_OP,	KEY_FASTFORWARD },
	{ NULL }
};

static GSList *avctp_callbacks = NULL;

static void auth_cb(DBusError *derr, void *user_data);

static int send_meta_data(struct control *control, uint8_t trans_id,
				uint8_t att_mask);
static int send_meta_data_continue_response(struct control *control,
				uint8_t trans_id);
static int send_notification(struct control *control,
		uint16_t event_id, uint16_t event_data);
static int send_play_status(struct control *control, uint32_t song_len,
                        uint32_t song_position, uint8_t play_status);

static sdp_record_t *avrcp_ct_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrct;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM;
	uint16_t avrcp_ver = 0x0100, avctp_ver = 0x0103, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrct, AV_REMOTE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrct);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP CT", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static sdp_record_t *avrcp_tg_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM;
	uint16_t browsing_psm = AVCTP_BROWSING_PSM;
	uint16_t avrcp_ver = 0x0103, avctp_ver = 0x0103, feat = 0x000f;

#ifdef ANDROID
	feat = 0x0001;
#endif
	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrtg);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static int send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct uinput_event event;

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	return write(fd, &event, sizeof(event));
}

static void send_key(int fd, uint16_t key, int pressed)
{
	if (fd < 0)
		return;

	send_event(fd, EV_KEY, key, pressed);
	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

static void handle_panel_passthrough(struct control *control,
					const unsigned char *operands,
					int operand_count)
{
	const char *status;
	int pressed, i;

	if (operand_count == 0)
		return;

	if (operands[0] & 0x80) {
		status = "released";
		pressed = 0;
	} else {
		status = "pressed";
		pressed = 1;
	}

	for (i = 0; key_map[i].name != NULL; i++) {
		uint8_t key_quirks;

		if ((operands[0] & 0x7F) != key_map[i].avrcp)
			continue;

		DBG("AVRCP: %s %s", key_map[i].name, status);

		key_quirks = control->key_quirks[key_map[i].avrcp];

		if (key_quirks & QUIRK_NO_RELEASE) {
			if (!pressed) {
				DBG("AVRCP: Ignoring release");
				break;
			}

			DBG("AVRCP: treating key press as press + release");
			send_key(control->uinput, key_map[i].uinput, 1);
			send_key(control->uinput, key_map[i].uinput, 0);
			break;
		}

		send_key(control->uinput, key_map[i].uinput, pressed);
		break;
	}

	if (key_map[i].name == NULL)
		DBG("AVRCP: unknown button 0x%02X %s",
						operands[0] & 0x7F, status);
}

static void avctp_disconnected(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (!control)
		return;

	if (control->io) {
		g_io_channel_shutdown(control->io, TRUE, NULL);
		g_io_channel_unref(control->io);
		control->io = NULL;
	}

	if (control->io_id) {
		g_source_remove(control->io_id);
		control->io_id = 0;

		if (control->state == AVCTP_STATE_CONNECTING)
			audio_device_cancel_authorization(dev, auth_cb,
								control);
	}

	if (control->uinput >= 0) {
		char address[18];

		ba2str(&dev->dst, address);
		DBG("AVRCP: closing uinput for %s", address);

		ioctl(control->uinput, UI_DEV_DESTROY);
		close(control->uinput);
		control->uinput = -1;
	}
}

static void avctp_set_state(struct control *control, avctp_state_t new_state)
{
	GSList *l;
	struct audio_device *dev = control->dev;
	avctp_state_t old_state = control->state;
	gboolean value;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		DBG("AVCTP Disconnected");

		avctp_disconnected(control->dev);

		if (old_state != AVCTP_STATE_CONNECTED)
			break;

		value = FALSE;
		g_dbus_emit_signal(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);

		if (!audio_device_is_active(dev, NULL))
			audio_device_set_authorized(dev, FALSE);

		break;
	case AVCTP_STATE_CONNECTING:
		DBG("AVCTP Connecting");
		break;
	case AVCTP_STATE_CONNECTED:
		DBG("AVCTP Connected");
		value = TRUE;
		g_dbus_emit_signal(control->dev->conn, control->dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_INVALID);
		emit_property_changed(control->dev->conn, control->dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &value);
		break;
	default:
		error("Invalid AVCTP state %d", new_state);
		return;
	}

	control->state = new_state;

	for (l = avctp_callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		cb->cb(control->dev, old_state, new_state, cb->user_data);
	}
}

static void set_company_id(uint8_t cid[3], const uint32_t cid_in)
{
	cid[0] = cid_in >> 16;
	cid[1] = cid_in >> 8;
	cid[2] = cid_in;
}

static gboolean control_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct control *control = data;
	unsigned char buf[1024], *operands;
	struct avctp_header *avctp;
	struct avrcp_header *avrcp;
	struct avrcp_params *params;
	int ret, packet_size, operand_count, sock;
	struct meta_data *mdata = control->mdata;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		goto failed;

	sock = g_io_channel_unix_get_fd(control->io);

	ret = read(sock, buf, sizeof(buf));
	if (ret <= 0)
		goto failed;

	DBG("Got %d bytes of data for AVCTP session %p", ret, control);

	if ((unsigned int) ret < sizeof(struct avctp_header)) {
		error("Too small AVCTP packet");
		goto failed;
	}

	packet_size = ret;

	avctp = (struct avctp_header *) buf;

	DBG("AVCTP transaction %u, packet type %u, C/R %u, IPID %u, "
			"PID 0x%04X",
			avctp->transaction, avctp->packet_type,
			avctp->cr, avctp->ipid, ntohs(avctp->pid));

	if ((unsigned int) ret < sizeof(struct avrcp_header)) {
		error("Too small AVRCP packet");
		goto failed;
	}

	avrcp = (struct avrcp_header *) buf;

	operands = buf + sizeof(struct avrcp_header);
	operand_count = ret - sizeof(struct avrcp_header);
	params = (struct avrcp_params *)buf;

	DBG("AVRCP %s 0x%01X, subunit_type 0x%02X, subunit_id 0x%01X, "
			"opcode 0x%02X, %d operands",
			avctp->cr ? "response" : "command",
			avrcp->code, avrcp->subunit_type, avrcp->subunit_id,
			avrcp->opcode, operand_count);

	if (avctp->packet_type != AVCTP_PACKET_SINGLE) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_NOT_IMPLEMENTED;
	} else if (avctp->pid != htons(AV_REMOTE_SVCLASS_ID)) {
		avctp->ipid = 1;
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_REJECTED;
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->code == CTYPE_CONTROL &&
			avrcp->subunit_type == SUBUNIT_PANEL &&
			avrcp->opcode == OP_PASSTHROUGH) {
		handle_panel_passthrough(control, operands, operand_count);
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_ACCEPTED;
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->code == CTYPE_STATUS &&
			(avrcp->opcode == OP_UNITINFO
			|| avrcp->opcode == OP_SUBUNITINFO)) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_STABLE;
		/* The first operand should be 0x07 for the UNITINFO response.
		 * Neither AVRCP (section 22.1, page 117) nor AVC Digital
		 * Interface Command Set (section 9.2.1, page 45) specs
		 * explain this value but both use it */
		if (operand_count >= 1 && avrcp->opcode == OP_UNITINFO)
			operands[0] = 0x07;
		if (operand_count >= 2)
			operands[1] = SUBUNIT_PANEL << 3;
		DBG("reply to %s", avrcp->opcode == OP_UNITINFO ?
				"OP_UNITINFO" : "OP_SUBUNITINFO");
	} else if (avctp->cr == AVCTP_COMMAND &&
			(avrcp->code == CTYPE_STATUS || avrcp->code == CTYPE_NOTIFY
			|| avrcp->code == CTYPE_CONTROL) &&
			avrcp->opcode == OP_VENDORDEPENDENT) {
		int error_code = -1;
		struct avrcp_caps *caps = (struct avrcp_caps *) buf;
		operands = (unsigned char *)caps + sizeof(struct avrcp_caps);

		DBG("Got Vendor Dep opcode");

		if (params->pdu_id == PDU_GET_CAPABILITY_ID &&
			!(control->avrcp_quirks & QUIRK_NO_CAPABILITIES)) {
			DBG("Pdu id is PDU_GET_CAPABILITY_ID");
			avctp->cr = AVCTP_RESPONSE;
			if (caps->capability_id == CAP_COMPANY_ID) {
				avrcp->code = CTYPE_STABLE;
				params->param_len = htons(5);
				operands[0] = 0x1; // Capability Count
				set_company_id(operands + 1, IEEEID_BTSIG);
				packet_size = sizeof(struct avrcp_caps) + 4;
			} else if (caps->capability_id == CAP_EVENTS_SUPPORTED_ID) {
				avrcp->code = CTYPE_STABLE;
				params->param_len = htons(4);
				operands[0] = 0x2; // Capability Count
				operands[1] = EVENT_PLAYBACK_STATUS_CHANGED;
				operands[2] = EVENT_TRACK_CHANGED;
				packet_size = sizeof(struct avrcp_caps) + 3;
			} else {
				error_code = ERROR_INVALID_PARAMETER;
			}
		} else if (params->pdu_id == PDU_LIST_PLAYER_APP_SETT_ATTR &&
				!(control->avrcp_quirks & QUIRK_NO_CAPABILITIES)) {
			operands = (unsigned char *)caps + sizeof(struct avrcp_params);
			avctp->cr = AVCTP_RESPONSE;
			avrcp->code = CTYPE_STABLE;
			params->param_len = htons(1);
			operands[0] = 0; // attribute count
			packet_size = sizeof(struct avrcp_params) + 1;
		} else if (params->pdu_id == PDU_GET_ELEMENT_ATTRIBUTES &&
				!(control->avrcp_quirks & QUIRK_NO_METADATA)) {
			DBG("Pdu id is PDU_GET_ELEMENT_ATTRIBUTES");
			struct avrcp_cmd_get_elem_attributes_req *attr =
				(struct avrcp_cmd_get_elem_attributes_req *) params;
			DBG("Received att_count is %d", attr->count);
			uint8_t att_mask = 0, index;
			for (index = 0; index < attr->count; index++) {
				int att_val = htonl(attr->attributes[index]);
				int mask = 1 << (att_val - 1);
				if (mask & METADATA_SUPPORTED_MASK) {
					att_mask |= mask;
				}
			}
			if (att_mask == 0) {
				att_mask = METADATA_SUPPORTED_MASK;
			}
			DBG("MetaData mask is %d att_count is %d", att_mask, attr->count);
			send_meta_data(control, avctp->transaction, att_mask);
			return TRUE;
		} else if (params->pdu_id == PDU_REQ_CONTINUE_RSP_ID) {
			if (mdata->remaining_mdata_len == 0) {
				error_code = ERROR_INVALID_PARAMETER;
			} else {
				send_meta_data_continue_response(control, avctp->transaction);
				return TRUE;
			}

		} else if (params->pdu_id == PDU_ABORT_CONTINUE_RSP_ID) {
			if (mdata->remaining_mdata_len == 0) {
				error_code = ERROR_INVALID_PARAMETER;
			} else {
				mdata->remaining_mdata_len = 0;
				g_free(mdata->remaining_mdata);
				mdata->remaining_mdata = NULL;
				avctp->cr = AVCTP_RESPONSE;
				avrcp->code = CTYPE_STABLE;
			}
		} else if (params->pdu_id == PDU_RGR_NOTIFICATION_ID &&
				!(control->avrcp_quirks & QUIRK_NO_NOTIFICATIONS)) {
			avctp->cr = AVCTP_RESPONSE;
			if (caps->capability_id == EVENT_TRACK_CHANGED) {
				mdata->trans_id_event_track = avctp->transaction;
				mdata->reg_track_changed = TRUE;
				avrcp->code = CTYPE_INTERIM;
				int index;
				if (mdata->current_play_status == STATUS_STOPPED) {
					for (index = 0; index < 8; index++, operands++)
						*operands = 0xFF;
				} else {
					for (index = 0; index < 8; index++, operands++)
						*operands = 0x00;
				}
				params->param_len = htons(9);
				packet_size = sizeof(struct avrcp_caps) + 8;
			} else if (caps->capability_id == EVENT_PLAYBACK_STATUS_CHANGED) {
				mdata->trans_id_event_playback = avctp->transaction;
				mdata->reg_playback_status = TRUE;
				avrcp->code = CTYPE_INTERIM;
				params->param_len = htons(2);
				*operands = mdata->current_play_status;
				packet_size = sizeof(struct avrcp_caps) + 1;
			} else {
				error_code = ERROR_INVALID_PARAMETER;
			}
		} else if (params->pdu_id == PDU_GET_PLAY_STATUS_ID &&
				!(control->avrcp_quirks & QUIRK_NO_NOTIFICATIONS)) {
			g_dbus_emit_signal(control->dev->conn, control->dev->path,
					AUDIO_CONTROL_INTERFACE, "GetPlayStatus",
					DBUS_TYPE_INVALID);
			mdata->trans_id_get_play_status = avctp->transaction;
			mdata->req_get_play_status = TRUE;
			return TRUE;
		} else {
			error_code = ERROR_INVALID_PDU;
		}

		if (error_code >= 0) {
			avctp->cr = AVCTP_RESPONSE;
			avrcp->code = CTYPE_REJECTED;
			params->param_len = htons(1);
			caps->capability_id = error_code;
			packet_size = sizeof(struct avrcp_caps);
		}
	} else {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_REJECTED;
	}
	ret = write(sock, buf, packet_size);
	if (ret != packet_size)
		goto failed;

	return TRUE;

failed:
	DBG("AVCTP session %p got disconnected", control);
	avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
	return FALSE;
}

static int uinput_create(char *name)
{
	struct uinput_dev dev;
	int fd, err, i;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = errno;
				error("Can't open input device: %s (%d)",
							strerror(err), err);
				return -err;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));
	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE - 1);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = errno;
		error("Can't write device information: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	for (i = 0; key_map[i].name != NULL; i++)
		ioctl(fd, UI_SET_KEYBIT, key_map[i].uinput);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = errno;
		error("Can't create uinput device: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	return fd;
}

static void init_uinput(struct control *control)
{
	struct audio_device *dev = control->dev;
	char address[18], name[248 + 1], *uinput_dev_name;

	device_get_name(dev->btd_dev, name, sizeof(name));
	if (g_str_equal(name, "Nokia CK-20W")) {
		control->key_quirks[FORWARD_OP] |= QUIRK_NO_RELEASE;
		control->key_quirks[BACKWARD_OP] |= QUIRK_NO_RELEASE;
		control->key_quirks[PLAY_OP] |= QUIRK_NO_RELEASE;
		control->key_quirks[PAUSE_OP] |= QUIRK_NO_RELEASE;
	}

	ba2str(&dev->dst, address);

	/* Use device name from config file if specified */
	uinput_dev_name = input_device_name;
	if (!uinput_dev_name)
		uinput_dev_name = address;

	control->uinput = uinput_create(uinput_dev_name);
	if (control->uinput < 0)
		error("AVRCP: failed to init uinput for %s", address);
	else
		DBG("AVRCP: uinput initialized for %s", address);
}

static void avctp_connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct control *control = data;
	char address[18];
	uint16_t imtu;
	GError *gerr = NULL;

	if (err) {
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_DEST, &address,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		error("%s", gerr->message);
		g_error_free(gerr);
		return;
	}

	DBG("AVCTP: connected to %s", address);

	if (!control->io)
		control->io = g_io_channel_ref(chan);

	init_uinput(control);

	avctp_set_state(control, AVCTP_STATE_CONNECTED);
	control->mtu = imtu;
	control->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) control_cb, control);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct control *control = user_data;
	GError *err = NULL;

	if (control->io_id) {
		g_source_remove(control->io_id);
		control->io_id = 0;
	}

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		return;
	}

	if (!bt_io_accept(control->io, avctp_connect_cb, control,
								NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
	}
}

static void avctp_confirm_cb(GIOChannel *chan, gpointer data)
{
	struct control *control = NULL;
	struct audio_device *dev;
	char address[18];
	bdaddr_t src, dst;
	GError *err = NULL;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	dev = manager_get_device(&src, &dst, TRUE);
	if (!dev) {
		error("Unable to get audio device object for %s", address);
		goto drop;
	}

	if (!dev->control) {
		btd_device_add_uuid(dev->btd_dev, AVRCP_REMOTE_UUID);
		if (!dev->control)
			goto drop;
	}

	control = dev->control;

	if (control->io) {
		error("Refusing unexpected connect from %s", address);
		goto drop;
	}

	avctp_set_state(control, AVCTP_STATE_CONNECTING);
	control->io = g_io_channel_ref(chan);

	if (audio_device_request_authorization(dev, AVRCP_TARGET_UUID,
						auth_cb, dev->control) < 0)
		goto drop;

	control->io_id = g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							control_cb, control);
	return;

drop:
	if (!control || !control->io)
		g_io_channel_shutdown(chan, TRUE, NULL);
	if (control)
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
}

static GIOChannel *avctp_server_socket(const bdaddr_t *src, gboolean master)
{
	GError *err = NULL;
	GIOChannel *io;

	io = bt_io_listen(BT_IO_L2CAP, NULL, avctp_confirm_cb, NULL,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
	}

	return io;
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct control *control = dev->control;
	GError *err = NULL;
	GIOChannel *io;

	if (control->state > AVCTP_STATE_DISCONNECTED)
		return TRUE;

	avctp_set_state(control, AVCTP_STATE_CONNECTING);

	io = bt_io_connect(BT_IO_L2CAP, avctp_connect_cb, control, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_INVALID);
	if (err) {
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		error("%s", err->message);
		g_error_free(err);
		return FALSE;
	}

	control->io = io;

	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (!(control && control->io))
		return;

	avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
}

int avrcp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config)
{
	sdp_record_t *record;
	gboolean tmp, master = TRUE;
	GError *err = NULL;
	struct avctp_server *server;

	if (config) {
		tmp = g_key_file_get_boolean(config, "General",
							"Master", &err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			g_error_free(err);
		} else
			master = tmp;
		err = NULL;
		input_device_name = g_key_file_get_string(config,
			"AVRCP", "InputDeviceName", &err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			input_device_name = NULL;
			g_error_free(err);
		}
	}

	server = g_new0(struct avctp_server, 1);
	if (!server)
		return -ENOMEM;

	if (!connection)
		connection = dbus_connection_ref(conn);

	record = avrcp_tg_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP target service record");
		g_free(server);
		sdp_record_free(record);
		return -1;
	}
	server->tg_record_id = record->handle;

#ifndef ANDROID
	record = avrcp_ct_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP controller service record");
		sdp_record_free(record);
		g_free(server);
		return -1;
	}
	server->ct_record_id = record->handle;
#endif

	server->io = avctp_server_socket(src, master);
	if (!server->io) {
#ifndef ANDROID
		remove_record_from_server(server->ct_record_id);
#endif
		remove_record_from_server(server->tg_record_id);
		g_free(server);
		return -1;
	}

	bacpy(&server->src, src);

	servers = g_slist_append(servers, server);

	return 0;
}

static struct avctp_server *find_server(GSList *list, const bdaddr_t *src)
{
	for (; list; list = list->next) {
		struct avctp_server *server = list->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

void avrcp_unregister(const bdaddr_t *src)
{
	struct avctp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	servers = g_slist_remove(servers, server);

#ifndef ANDROID
	remove_record_from_server(server->ct_record_id);
#endif
	remove_record_from_server(server->tg_record_id);

	g_io_channel_shutdown(server->io, TRUE, NULL);
	g_io_channel_unref(server->io);
	g_free(server);

	if (servers)
		return;

	dbus_connection_unref(connection);
	connection = NULL;
}

static DBusMessage *control_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	connected = (control->state == AVCTP_STATE_CONNECTED);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return reply;
}

static int avctp_send_passthrough(struct control *control, uint8_t op)
{
	unsigned char buf[sizeof(struct avrcp_header) + 2];
	struct avrcp_header *avrcp = (struct avrcp_header *) buf;
	struct avctp_header *avctp = &avrcp->avctp;
	uint8_t *operands = &buf[sizeof(struct avrcp_header)];
	int err, sk = g_io_channel_unix_get_fd(control->io);
	static uint8_t transaction = 0;

	memset(buf, 0, sizeof(buf));

	avctp->transaction = transaction++;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_COMMAND;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avrcp->code = CTYPE_CONTROL;
	avrcp->subunit_type = SUBUNIT_PANEL;
	avrcp->opcode = OP_PASSTHROUGH;

	operands[0] = op & 0x7f;
	operands[1] = 0;

	if (write(sk, buf, sizeof(buf)) < 0)
		return -errno;

	/* Button release */
	avctp->transaction = transaction++;
	operands[0] |= 0x80;

	if (write(sk, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

static DBusMessage *volume_up(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessage *reply;
	int err;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (control->state != AVCTP_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control, VOL_UP_OP);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *volume_down(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessage *reply;
	int err;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (control->state != AVCTP_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control, VOL_DOWN_OP);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *update_notification(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	struct meta_data *mdata = control->mdata;
	DBusMessage *reply;
	uint16_t event_id;
	uint64_t event_data;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT16, &event_id,
						DBUS_TYPE_UINT64, &event_data,
						DBUS_TYPE_INVALID) == FALSE) {
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
	}

	DBG("Notification data is %d %d", (int)event_id, (int)event_data);

	if (control->state != AVCTP_STATE_CONNECTED)
		return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NotConnected",
				"Device not Connected");

	send_notification(control, event_id, event_data);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *update_play_status(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	struct meta_data *mdata = control->mdata;
	DBusMessage *reply;
	uint32_t duration, position;
	uint32_t play_status;
	int err;
        DBG("update_play_status called");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &duration,
						DBUS_TYPE_UINT32, &position,
						DBUS_TYPE_UINT32, &play_status,
						DBUS_TYPE_INVALID) == FALSE) {
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
	}

	DBG("PlayStatus data is %d %d %d", duration, position, play_status);
	mdata->current_play_status = (uint8_t)play_status;

	if (control->state != AVCTP_STATE_CONNECTED)
		return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NotConnected",
				"Device not Connected");

	send_play_status(control, duration, position, play_status);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *update_metadata(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	struct meta_data *mdata = control->mdata;
	DBusMessage *reply;
	const gchar *title, *artist, *album;
	const gchar *media_number, *total_media_count, *playing_time;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &title,
						DBUS_TYPE_STRING, &artist,
						DBUS_TYPE_STRING, &album,
						DBUS_TYPE_STRING, &media_number,
						DBUS_TYPE_STRING, &total_media_count,
						DBUS_TYPE_STRING, &playing_time,
						DBUS_TYPE_INVALID) == FALSE) {
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
	}

	DBG("MetaData is %s %s %s %s %s %s", title, artist, album, media_number,
			total_media_count, playing_time);
	if (strlen(title) < METADATA_MAX_STRING_LEN)
		strcpy(mdata->title, title);
	else
		strncpy(mdata->title, title, (METADATA_MAX_STRING_LEN-1));
	if (strlen(artist) < METADATA_MAX_STRING_LEN)
		strcpy(mdata->artist, artist);
	else
		strncpy(mdata->artist, artist, (METADATA_MAX_STRING_LEN-1));
	if (strlen(album) < METADATA_MAX_STRING_LEN)
		strcpy(mdata->album, album);
	else
		strncpy(mdata->album, album, (METADATA_MAX_STRING_LEN-1));
	if (strlen(media_number) < METADATA_MAX_NUMBER_LEN)
		strcpy(mdata->media_number, media_number);
	else
		strncpy(mdata->media_number, media_number, (METADATA_MAX_NUMBER_LEN-1));
	if (strlen(total_media_count) < METADATA_MAX_NUMBER_LEN)
		strcpy(mdata->total_media_count, total_media_count);
	else
		strncpy(mdata->total_media_count, total_media_count, (METADATA_MAX_NUMBER_LEN-1));
	if (strlen(playing_time) < METADATA_MAX_NUMBER_LEN)
		strcpy(mdata->playing_time, playing_time);
	else
		strncpy(mdata->playing_time, playing_time, (METADATA_MAX_NUMBER_LEN-1));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *control_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gboolean value;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	value = (device->control->state == AVCTP_STATE_CONNECTED);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable control_methods[] = {
	{ "IsConnected",	"",	"b",	control_is_connected,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetProperties",	"",	"a{sv}",control_get_properties },
	{ "VolumeUp",		"",	"",	volume_up },
	{ "VolumeDown",		"",	"",	volume_down },
	{ "UpdateMetaData",	"ssssss",	"",	update_metadata },
	{ "UpdatePlayStatus",	"uuu",	"",	update_play_status },
	{ "UpdateNotification",	"qt",	"",	update_notification },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable control_signals[] = {
	{ "Connected",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "Disconnected",		"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "PropertyChanged",		"sv"	},
	{ "GetPlayStatus",		""	},
	{ NULL, NULL }
};

static void metadata_cleanup(struct meta_data *mdata) {
	if (mdata->title) {
		g_free(mdata->title);
		mdata->title = NULL;
	}
	if (mdata->artist) {
		g_free(mdata->artist);
		mdata->artist = NULL;
	}
	if (mdata->album) {
		g_free(mdata->album);
		mdata->album = NULL;
	}
	if (mdata->media_number) {
		g_free(mdata->media_number);
		mdata->media_number = NULL;
	}
	if (mdata->total_media_count) {
		g_free(mdata->total_media_count);
		mdata->total_media_count = NULL;
	}
	if (mdata->playing_time) {
		g_free(mdata->playing_time);
		mdata->playing_time = NULL;
	}
	if (mdata->remaining_mdata) {
		g_free(mdata->remaining_mdata);
		mdata->remaining_mdata = NULL;
		mdata->remaining_mdata_len = 0;
	}

}

static void path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct control *control = dev->control;

	DBG("Unregistered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	if (control->state != AVCTP_STATE_DISCONNECTED)
		avctp_disconnected(dev);

	metadata_cleanup(control->mdata);
	g_free(control->mdata);
	g_free(control);
	dev->control = NULL;
}

void control_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
		AUDIO_CONTROL_INTERFACE);
}

void control_update(struct audio_device *dev, uint16_t uuid16)
{
	struct control *control = dev->control;

	if (uuid16 == AV_REMOTE_TARGET_SVCLASS_ID)
		control->target = TRUE;
}

static uint8_t get_avrcp_quirks(struct audio_device *dev)
{
	char name[MAX_NAME_LENGTH + 1];
	uint8_t quirks = 0;

	device_get_name(dev->btd_dev, name, sizeof(name));

	if (g_str_equal(name, "Ford Audio")) {
		/* The Sony car stereo Ford is using under their brand as
		 * '6000 CD' has a completely broken AVRCP 1.3 implementation.
		 * After recognizing AVRCP 1.3 TG capabilities and exchanging
		 * a few PDUs, the car stereo disconnects and reconnects BT,
		 * also resetting USB devices if connected to it.
		 * To avoid that and allow at least HFP and A2DP to work,
		 * prevent any AVRCP 1.3 PDUs from being sent.
		 */
		quirks |= QUIRK_NO_CAPABILITIES;
		quirks |= QUIRK_NO_METADATA;
		quirks |= QUIRK_NO_NOTIFICATIONS;
	}

	return quirks;
}

struct control *control_init(struct audio_device *dev, uint16_t uuid16)
{
	struct control *control;
	struct meta_data *mdata;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					control_methods, control_signals, NULL,
					dev, path_unregister))
		return NULL;

	DBG("Registered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	control = g_new0(struct control, 1);
	control->dev = dev;
	control->state = AVCTP_STATE_DISCONNECTED;
	control->uinput = -1;
	control->avrcp_quirks = get_avrcp_quirks(dev);

	if (uuid16 == AV_REMOTE_TARGET_SVCLASS_ID)
		control->target = TRUE;

	mdata = g_new0(struct meta_data, 1);
	if (!mdata) {
		DBG("No Memory available for meta data");
		return NULL;
	}
	mdata->title = g_new0(gchar, METADATA_MAX_STRING_LEN);
	mdata->artist = g_new0(gchar, METADATA_MAX_STRING_LEN);
	mdata->album = g_new0(gchar, METADATA_MAX_STRING_LEN);
	mdata->media_number = g_new0(gchar, METADATA_MAX_NUMBER_LEN);
	mdata->total_media_count = g_new0(gchar, METADATA_MAX_NUMBER_LEN);
	mdata->playing_time = g_new0(gchar, METADATA_MAX_NUMBER_LEN);

	if (!(mdata->title) || !(mdata->artist) || !(mdata->album) ||
			!(mdata->media_number) || !(mdata->total_media_count) ||
			!(mdata->playing_time)) {
		DBG("No Memory available for meta data");
		metadata_cleanup(mdata);
		g_free(mdata);
		return NULL;
	}

	strcpy(mdata->title,DEFAULT_METADATA_STRING);
	strcpy(mdata->artist,DEFAULT_METADATA_STRING);
	strcpy(mdata->album,DEFAULT_METADATA_STRING);
	strcpy(mdata->media_number,DEFAULT_METADATA_NUMBER);
	strcpy(mdata->total_media_count,DEFAULT_METADATA_NUMBER);
	strcpy(mdata->playing_time,DEFAULT_METADATA_NUMBER);
	mdata->remaining_mdata = NULL;
	mdata->remaining_mdata_len = 0;
	mdata->trans_id_event_track = 0;
	mdata->trans_id_event_playback = 0;
	mdata->trans_id_event_addressed_player = 0;
	mdata->trans_id_event_available_player = 0;
	mdata->trans_id_get_play_status = 0;
	mdata->reg_track_changed = FALSE;
	mdata->reg_playback_status = FALSE;
	mdata->reg_addressed_player = FALSE;
	mdata->reg_available_player = FALSE;
	mdata->req_get_play_status = FALSE;
	mdata->current_play_status = STATUS_STOPPED;

	control->mdata = mdata;

	return control;
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control && control->state != AVCTP_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

unsigned int avctp_add_state_cb(avctp_state_cb cb, void *user_data)
{
	struct avctp_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct avctp_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	avctp_callbacks = g_slist_append(avctp_callbacks, state_cb);

	return state_cb->id;
}

gboolean avctp_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = avctp_callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			avctp_callbacks = g_slist_remove(avctp_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

static int send_meta_data_continue_response(struct control *control,
						uint8_t trans_id)
{
	struct meta_data *mdata = control->mdata;
	int header_len = sizeof(struct avrcp_params);
	int meta_data_len = mdata->remaining_mdata_len;
	unsigned char buf[meta_data_len + header_len];
	struct avrcp_params *params = (struct avrcp_params *) buf;
	struct avrcp_header *avrcp = &params->avrcp;
	struct avctp_header *avctp = &avrcp->avctp;
	int sk = g_io_channel_unix_get_fd(control->io);

	memset(buf, 0, sizeof(buf));

	avctp->transaction = trans_id;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_RESPONSE;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avrcp->code = CTYPE_STABLE;
	avrcp->subunit_type = SUBUNIT_PANEL;
	avrcp->opcode = OP_VENDORDEPENDENT;

	set_company_id(params->company_id, IEEEID_BTSIG);
	params->pdu_id = PDU_GET_ELEMENT_ATTRIBUTES;

	memcpy(buf + header_len, mdata->remaining_mdata, mdata->remaining_mdata_len);

	if (meta_data_len + header_len - sizeof(struct avctp_header) > AVRCP_MAX_PKT_SIZE) {
		int possible_len = AVRCP_MAX_PKT_SIZE - header_len + sizeof(struct avctp_header);

		memcpy(mdata->remaining_mdata, buf + header_len + possible_len,
		       mdata->remaining_mdata_len - possible_len);
		mdata->remaining_mdata_len -= possible_len;

		params->packet_type = AVCTP_PACKET_CONTINUE;
		meta_data_len = possible_len;
	} else {
		params->packet_type = AVCTP_PACKET_END;

		g_free(mdata->remaining_mdata);
		mdata->remaining_mdata = NULL;
		mdata->remaining_mdata_len = 0;
	}

	params->param_len = htons(meta_data_len);

	return write(sk, buf, meta_data_len + header_len);
}

static int send_meta_data(struct control *control, uint8_t trans_id, uint8_t att_mask)
{
	struct meta_data *mdata = control->mdata;
	int header_len = sizeof(struct avrcp_caps);
	/* calculate for the worst case */
	int meta_data_len = strlen(mdata->title) + strlen(mdata->artist) +
		strlen(mdata->album) + strlen(mdata->media_number) +
		strlen(mdata->total_media_count) + strlen(mdata->playing_time) +
		(sizeof(struct meta_data_field) * METADATA_MAX_FIELDS);
	unsigned char buf[meta_data_len + header_len];
	struct avrcp_caps *caps = (struct avrcp_caps *) buf;
	struct avrcp_params *params = &caps->params;
	struct avrcp_header *avrcp = &params->avrcp;
	struct avctp_header *avctp = &avrcp->avctp;
	struct meta_data_field *mdata_field = (struct meta_data_field *) &buf[header_len];
	int count = 0, len = 0, total_len = 0, sk = g_io_channel_unix_get_fd(control->io);
	uint8_t *op;

	memset(buf, 0, sizeof(buf));

	avctp->transaction = trans_id;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_RESPONSE;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avrcp->code = CTYPE_STABLE;
	avrcp->subunit_type = SUBUNIT_PANEL;
	avrcp->opcode = OP_VENDORDEPENDENT;

	set_company_id(params->company_id, IEEEID_BTSIG);
	params->pdu_id = PDU_GET_ELEMENT_ATTRIBUTES;
	params->packet_type = AVCTP_PACKET_SINGLE;
	DBG("Att mask is %d", att_mask);

	meta_data_len = 0;
	op = (uint8_t *) mdata_field;

	if (att_mask & (1 << (METADATA_TITLE - 1))) {
		mdata_field->att_id = htonl(METADATA_TITLE);
		mdata_field->char_set_id = htons(CHARACTER_SET_UTF8);
		len = strlen(mdata->title);
		mdata_field->att_len = htons(len);
		strncpy(mdata_field->val, mdata->title, len);
		meta_data_len += len + sizeof(struct meta_data_field);
		DBG("METADATA_TITLE %d %d", len, meta_data_len);
		count++;
	}

	if (att_mask & (1 << (METADATA_ARTIST - 1))) {
		if (len > 0) {
			op += sizeof(struct meta_data_field) + len;
		}
		mdata_field = (struct meta_data_field *)op;
		mdata_field->att_id = htonl(METADATA_ARTIST);
		mdata_field->char_set_id = htons(CHARACTER_SET_UTF8);
		len = strlen(mdata->artist);
		mdata_field->att_len = htons(len);
		strncpy(mdata_field->val, mdata->artist, len);
		meta_data_len += len + sizeof(struct meta_data_field);
		count++;
	}

	if (att_mask & (1 << (METADATA_ALBUM - 1))) {
		if (len > 0) {
			op += sizeof(struct meta_data_field) + len;
		}
		mdata_field = (struct meta_data_field *)op;
		mdata_field->att_id = htonl(METADATA_ALBUM);
		mdata_field->char_set_id = htons(CHARACTER_SET_UTF8);
		len = strlen(mdata->album);
		mdata_field->att_len = htons(len);
		strncpy(mdata_field->val, mdata->album, len);
		meta_data_len += len + sizeof(struct meta_data_field);
		count++;
	}

	if (att_mask & (1 << (METADATA_MEDIA_NUMBER - 1))) {
		if (len > 0) {
			op += sizeof(struct meta_data_field) + len;
		}
		mdata_field = (struct meta_data_field *)op;
		mdata_field->att_id = htonl(METADATA_MEDIA_NUMBER);
		mdata_field->char_set_id = htons(CHARACTER_SET_UTF8);
		len = strlen(mdata->media_number);
		mdata_field->att_len = htons(len);
		strncpy(mdata_field->val, mdata->media_number, len);
		meta_data_len += len + sizeof(struct meta_data_field);
		count++;
	}

	if (att_mask & (1 << (METADATA_TOTAL_MEDIA - 1))) {
		if (len > 0) {
			op += sizeof(struct meta_data_field) + len;
		}
		mdata_field = (struct meta_data_field *)op;
		mdata_field->att_id = htonl(METADATA_TOTAL_MEDIA);
		mdata_field->char_set_id = htons(CHARACTER_SET_UTF8);
		len = strlen(mdata->total_media_count);
		mdata_field->att_len = htons(len);
		strncpy(mdata_field->val, mdata->total_media_count, len);
		meta_data_len += len + sizeof(struct meta_data_field);
		count++;
	}

	if (att_mask & (1 << (METADATA_PLAYING_TIME - 1))) {
		if (len > 0) {
			op += sizeof(struct meta_data_field) + len;
		}
		mdata_field = (struct meta_data_field *)op;
		mdata_field->att_id = htonl(METADATA_PLAYING_TIME);
		mdata_field->char_set_id = htons(CHARACTER_SET_UTF8);
		len = strlen(mdata->playing_time);
		mdata_field->att_len = htons(len);
		strncpy(mdata_field->val, mdata->playing_time, len);
		meta_data_len += len + sizeof(struct meta_data_field);
		count++;
	}

	caps->capability_id = count;

	if ((meta_data_len + header_len - sizeof(struct avctp_header)) > AVRCP_MAX_PKT_SIZE) {
		int possible_len = AVRCP_MAX_PKT_SIZE - header_len + sizeof(struct avctp_header);
		DBG("meta len is %d header len is %d -> possible %d", meta_data_len, header_len, possible_len);

		params->packet_type = AVCTP_PACKET_START;

		mdata->remaining_mdata = g_new0(gchar, meta_data_len - possible_len);
		if (!(mdata->remaining_mdata)) {
			return -ENOMEM;
		}
		mdata->remaining_mdata_len = meta_data_len - possible_len;
		DBG("Remain meta data len is %d", mdata->remaining_mdata_len);

		memcpy(mdata->remaining_mdata, buf + header_len + possible_len,
		       mdata->remaining_mdata_len);
		meta_data_len = possible_len;
	}
	params->param_len = htons(meta_data_len + header_len - sizeof(struct avrcp_params));

	return write(sk, buf, meta_data_len + header_len);
}

static int send_notification(struct control *control,
		uint16_t event_id, uint16_t event_data)
{
	struct meta_data *mdata = control->mdata;
	struct avrcp_event event;
	struct avrcp_caps *caps = &event.caps;
	struct avrcp_params *params = &caps->params;
	struct avrcp_header *avrcp = &params->avrcp;
	struct avctp_header *avctp = &avrcp->avctp;
	int len = 0, total_len = 0, sk = g_io_channel_unix_get_fd(control->io);

	memset(&event, 0, sizeof(event));

	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_RESPONSE;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avrcp->code = CTYPE_CHANGED;
	avrcp->subunit_type = SUBUNIT_PANEL;
	avrcp->opcode = OP_VENDORDEPENDENT;

	set_company_id(params->company_id, IEEEID_BTSIG);
	params->pdu_id = PDU_RGR_NOTIFICATION_ID;
	params->packet_type = AVCTP_PACKET_SINGLE;
	caps->capability_id = event_id;

	switch(event_id) {
		case EVENT_TRACK_CHANGED:
			if (mdata->reg_track_changed == FALSE)
				return 0;
			total_len = sizeof(event.caps) + sizeof(event.event.track_changed);
			event.event.track_changed.track_high = 0;
			event.event.track_changed.track_low = htonl(event_data);
			avctp->transaction = mdata->trans_id_event_track;
			mdata->reg_track_changed = FALSE;
			break;
		case EVENT_PLAYBACK_STATUS_CHANGED:
			mdata->current_play_status = (uint8_t) event_data;
			if (mdata->reg_playback_status == FALSE)
				return 0;
			total_len = sizeof(event.caps) + sizeof(event.event.playback_status_changed);
			event.event.playback_status_changed.status = event_data;
			avctp->transaction = mdata->trans_id_event_playback;
			mdata->reg_playback_status = FALSE;
			break;
		case EVENT_ADDRESSED_PLAYER_CHANGED:
			if (mdata->reg_addressed_player == FALSE)
				return 0;
			total_len = sizeof(event.caps) + sizeof(event.event.player_changed);
			event.event.player_changed.player_id = htons(event_data);
			event.event.player_changed.uid_counter = 0;
			avctp->transaction = mdata->trans_id_event_addressed_player;
			mdata->reg_addressed_player = FALSE;
			break;
		case EVENT_AVAILABLE_PLAYERS_CHANGED:
			if (mdata->reg_available_player == FALSE)
				return 0;
			avctp->transaction = mdata->trans_id_event_available_player;
			mdata->reg_available_player = FALSE;
			total_len = sizeof(event.caps);
			break;
	}
	params->param_len = htons(total_len + 1 - sizeof(event.caps));
	DBG("Send Notification totallen %d", total_len);
	return write(sk, (unsigned char *) &event, total_len);
}

static int send_play_status(struct control *control, uint32_t song_len,
			uint32_t song_position, uint8_t play_status)
{
	struct meta_data *mdata = control->mdata;
	struct avrcp_play_status status;
	struct avrcp_header *avrcp = &status.params.avrcp;
	struct avctp_header *avctp = &avrcp->avctp;
	struct avrcp_params *params = &status.params;
	int sk = g_io_channel_unix_get_fd(control->io);
	uint8_t *op = (uint8_t *) params + sizeof(struct avrcp_header);

	DBG("send_play_status called");

	if (mdata->req_get_play_status == FALSE)
		return 0;

	DBG("send_play_status executing");
	memset(&status, 0, sizeof(status));
	mdata->req_get_play_status = FALSE;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_RESPONSE;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);
	avctp->transaction = mdata->trans_id_get_play_status;

	avrcp->code = CTYPE_STABLE;
	avrcp->subunit_type = SUBUNIT_PANEL;
	avrcp->opcode = OP_VENDORDEPENDENT;

	set_company_id(params->company_id, IEEEID_BTSIG);
	params->pdu_id = PDU_GET_PLAY_STATUS_ID;
	params->packet_type = AVCTP_PACKET_SINGLE;
	params->param_len = htons(sizeof(status) - sizeof(status.params));

	status.song_len = htonl(song_len);
	status.song_pos = htonl(song_position);
	status.play_status = play_status;

	return write(sk, (unsigned char *) &status, sizeof(status));
}

