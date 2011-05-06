// elliptics-fastcgi - FastCGI-module component for Elliptics file storage
// Copyright (C) 2011 Leonid A. Movsesjan <lmovsesjan@yandex-team.ru>

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "settings.h"

#include <sstream>

#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

#include <sys/socket.h>

#include <openssl/md5.h>

#include <fastcgi2/config.h>
#include <fastcgi2/component_factory.h>
#include <fastcgi2/cookie.h>
#include <fastcgi2/except.h>
#include <fastcgi2/util.h>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

#include "elliptics_fastcgi.hpp"

namespace elliptics {

enum dnet_common_embed_types {
	DNET_FCGI_EMBED_DATA	    = 1,
	DNET_FCGI_EMBED_TIMESTAMP,
};

struct dnet_common_embed {
	uint64_t		size;
	uint32_t		type;
	uint32_t		flags;
	uint8_t		 data[0];
};

static inline void
dnet_common_convert_embedded(struct dnet_common_embed *e) {
	e->size = dnet_bswap64(e->size);
	e->type = dnet_bswap32(e->type);
	e->flags = dnet_bswap32(e->flags);
}

static inline char*
file_backend_get_dir(const unsigned char *id, uint64_t bit_num, char *dst) {
	char *res = dnet_dump_id_len_raw(id, ALIGN(bit_num, 8) / 8, dst);

	if (res) {
		res[bit_num / 4] = '\0';
	}

	return res;
}

static int
dnet_common_prepend_data(struct timespec *ts, uint64_t size, char *buf, int *bufsize) {
	char *orig = buf;
	struct dnet_common_embed *e = (struct dnet_common_embed*)buf;
	uint64_t *edata = (uint64_t *)e->data;

	if (*bufsize < (int)(sizeof (struct dnet_common_embed) + sizeof (uint64_t)) * 2) {
		return -ENOBUFS;
	}

	e->size = sizeof (uint64_t) * 2;
	e->type = DNET_FCGI_EMBED_TIMESTAMP;
	e->flags = 0;
	dnet_common_convert_embedded(e);

	edata[0] = dnet_bswap64(ts->tv_sec);
	edata[1] = dnet_bswap64(ts->tv_nsec);

	buf += sizeof (struct dnet_common_embed) + sizeof (uint64_t) * 2;

	e = (struct dnet_common_embed*)buf;
	e->size = size;
	e->type = DNET_FCGI_EMBED_DATA;
	e->flags = 0;
	dnet_common_convert_embedded(e);

	buf += sizeof (struct dnet_common_embed);

	*bufsize = buf - orig;
	return 0;
}

EllipticsProxy::EllipticsProxy(fastcgi::ComponentContext *context) :
	fastcgi::Component(context),
	logger_(NULL) {
#ifdef HAVE_GEOBASE
	last_modified_ = 0;
#endif
}

EllipticsProxy::~EllipticsProxy() {
}

std::pair<std::string, time_t>
EllipticsProxy::secret(fastcgi::Request *request) const {
	if (request->hasCookie(cookie_name_)) {
		std::string cookie = request->getCookie(cookie_name_);

		Separator sep(".");
		Tokenizer tok(cookie, sep);

		if (paramsNum(tok) == 2) {
			return std::make_pair(request->getCookie(cookie_name_), time(NULL));
		}
	}

	boost::uint32_t rnd;

	int urandom = open("/dev/urandom", O_RDONLY);
	if (urandom < 0) {
		std::ostringstream ostr;
		ostr << "can not generate random bytes with errno " << -errno;
		throw std::runtime_error(ostr.str());
	}

	int err = read(urandom, &rnd, sizeof (rnd));

	close(urandom);
	if (err < 0) {
		err = -errno;

		std::ostringstream ostr;
		ostr << "can not generate random bytes with errno " << err;
		throw std::runtime_error(ostr.str());
	}

	time_t timestamp = time(NULL);
	std::ostringstream ostr;
	ostr << cookie_key_ << std::hex << rnd << std::hex << timestamp;

	char cookie[256];
	snprintf(cookie, sizeof (cookie), "%x.%lx.%s", rnd, timestamp, md5(ostr.str()).c_str());

	fastcgi::Cookie c(cookie_name_, cookie);
	c.expires(timestamp + cookie_expires_);
	c.path(cookie_path_);
	c.domain(cookie_domain_);

	request->setCookie(c);

	return std::make_pair(cookie, timestamp);
}

std::string
EllipticsProxy::md5(const std::string &source) {
	MD5_CTX md5handler;
	unsigned char md5buffer[16];

	MD5_Init(&md5handler);
	MD5_Update(&md5handler, (unsigned char *)source.c_str(), source.length());
	MD5_Final(md5buffer, &md5handler);

	char alpha[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	unsigned char c;
	std::string md5digest;
	md5digest.reserve(32);

	for (int i = 0; i < 16; ++i) {
		c = (md5buffer[i] & 0xf0) >> 4;
		md5digest.push_back(alpha[c]);
		c = (md5buffer[i] & 0xf);
		md5digest.push_back(alpha[c]);
	}

	return md5digest;
}

void
EllipticsProxy::handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context) {
	(void)context;
	try {
		std::string handler;
		if (request->getQueryString().length() != 0) {
			if (request->hasArg("stat") || request->hasArg("ping")) {
				handler = "stat";
			}
			else if (request->hasArg("stat_log")) {
				handler = "stat-log";
			}
			else if (request->hasArg("direct")) {
				handler = "get";
			}
			else if (request->hasArg("unlink")) {
				handler = "delete";
			}
			else {
				if (request->hasArg("name")) {
					handler = request->getServerPort() == write_port_ ? "upload" : "download-info";
				}
				else {
					handler = request->getScriptName().substr(1, std::string::npos);
				}
			}
		}
		else {
			handler = request->getScriptName().substr(1, std::string::npos);
		}
		std::string::size_type pos = handler.find('/');
		handler = handler.substr(0, pos);
		RequestHandlers::iterator it = handlers_.find(handler);
		if (handlers_.end() == it) {
			throw fastcgi::HttpException(404);
		}
		(this->*it->second)(request);
	}
	catch (const fastcgi::HttpException &e) {
		throw;
	}
	catch (...) {
		throw fastcgi::HttpException(400);
	}
}

void
EllipticsProxy::registerHandler(const char *name, RequestHandler handler) {
	RequestHandlers::iterator it = handlers_.find(name);
	if (handlers_.end() != it) {
		log()->error("repeated registration of %s handler", name);
		return;
	}
	handlers_.insert(std::make_pair(name, handler));
}

void
EllipticsProxy::onLoad() {
	assert(NULL == logger_);

	const fastcgi::Config *config = context()->getConfig();
	std::string path(context()->getComponentXPath());

	logger_ = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));
	if (!logger_) {
		throw std::logic_error("can't find logger");
	}

#ifdef HAVE_GEOBASE
	filename_ = config->asString(path + "/geobase/path");

	struct stat st;
	int result = stat(filename_.c_str(), &st);

	if (result != 0) {
		std::string msg = "can not locate geobase file " + filename_;
		throw std::runtime_error(msg.c_str());
	}

	lookup_.reset((new geobase3::lookup(filename_.c_str())));
	log()->info("loaded geobase index %s", filename_.c_str());
	
	boost::uint32_t timeout = config->asInt(path + "/geobase/timeout", 3600);
	boost::function<void()> func = boost::bind(&EllipticsProxy::refresh, this);
	refresher_.reset(new Refresher(func, timeout));
#endif

	state_num_ = config->asInt(path + "/dnet/die-limit");
	base_port_ = config->asInt(path + "/dnet/base-port");
	write_port_ = config->asInt(path + "/dnet/write-port", 9000);
	directory_bit_num_ = config->asInt(path + "/dnet/directory-bit-num");

	use_cookie_ = (config->asString(path + "/dnet/cookie/name", "") != "");

	if (use_cookie_) {
		cookie_name_ = config->asString(path + "/dnet/cookie/name");
		cookie_key_ = config->asString(path + "/dnet/cookie/key");
		cookie_path_ = config->asString(path + "/dnet/cookie/path");
		cookie_domain_ = config->asString(path + "/dnet/cookie/domain");
		cookie_expires_ = config->asInt(path + "/dnet/cookie/expires");
		sign_key_ = config->asString(path + "/dnet/cookie/sign");
	}

	std::string elliptics_log_filename = config->asString(path + "/dnet/log/path");
	uint32_t elliptics_log_mask = config->asInt(path + "/dnet/log/mask");
	elliptics_log_.reset(new elliptics_log_file(elliptics_log_filename.c_str(), elliptics_log_mask));

	struct dnet_config dnet_conf;
	memset(&dnet_conf, 0, sizeof (dnet_conf));

	dnet_conf.wait_timeout = config->asInt(path + "/dnet/wait-timeout", 0);
	dnet_conf.check_timeout = config->asInt(path + "/dnet/reconnect-timeout", 0);
	dnet_conf.flags = config->asInt(path + "/dnet/cfg-flags", 4);

	elliptics_node_.reset(new elliptics_node(*elliptics_log_, dnet_conf));

	std::vector<std::string> names;
	config->subKeys(path + "/dnet/remote/addr", names);

	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		std::string remote = config->asString(it->c_str());
		Separator sep(":");
		Tokenizer tok(remote, sep);

		if (paramsNum(tok) != 2) {
			log()->error("invalid dnet remote %s", remote.c_str());
			continue;
		}

		std::string addr;
		int port, family;

		try {
			Tokenizer::iterator tit = tok.begin();
			addr = *tit;
			port = boost::lexical_cast<int>(*(++tit));
			family = boost::lexical_cast<int>(*(++tit));
		}
		catch (...) {
			log()->error("invalid dnet remote %s", remote.c_str());
			continue;
		}

		try {
			remotes_.push_back(remote);
			elliptics_node_->add_remote(addr.c_str(), port, family);
			log()->info("added dnet remote %s:%d:%d", addr.c_str(), port, family);
		}
		catch (const std::exception &e) {
			log()->error("invalid dnet remote %s %s", remote.c_str(), e.what());
		}
		catch (...) {
			log()->error("invalid dnet remote %s", remote.c_str());
		}
	}

	names.clear();
	config->subKeys(path + "/dnet/allow/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		allow_list_.insert(config->asString(it->c_str()));
	}

	names.clear();
	config->subKeys(path + "/dnet/deny/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		deny_list_.insert(config->asString(it->c_str()));
	}

	std::string groups = config->asString(path + "/dnet/groups", "");

	Separator sep(":");
	Tokenizer tok(groups, sep);

	for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
		try {
			groups_.push_back(boost::lexical_cast<int>(*it));
		}
		catch (...) {
			log()->error("invalid dnet group id %s", it->c_str());
		}
	}

	if (groups_.size() != 0) {
		try {
			elliptics_node_->add_groups(groups_);
			log()->info("added dnet groups %s", groups.c_str());
		}
		catch (const std::exception &e) {
			log()->error("can not add dnet groups %s %s", groups.c_str(), e.what());
		}
		catch (...) {
			log()->error("can not add dnet groups %s", groups.c_str());
		}
	}

	success_copies_num_ = config->asInt(path + "/dnet/success-copies-num", groups_.size());

	std::vector<std::string> typemap;
	config->subKeys(path + "/dnet/typemap/type", typemap);

	for (std::vector<std::string>::iterator it = typemap.begin(), end = typemap.end(); end != it; ++it) {
		std::string match = config->asString(it->c_str());

		std::string::size_type pos = match.find("->");
		std::string extention = match.substr(0, pos);
		std::string type = match.substr(pos + sizeof ("->") - 1, std::string::npos);

		typemap_[extention] = type;
	}

	registerHandler("ping", &EllipticsProxy::pingHandler);
	registerHandler("download-info", &EllipticsProxy::downloadInfoHandler);
	registerHandler("get", &EllipticsProxy::getHandler);
	registerHandler("stat", &EllipticsProxy::pingHandler);
	registerHandler("stat_log", &EllipticsProxy::statLogHandler);
	registerHandler("stat-log", &EllipticsProxy::statLogHandler);
	registerHandler("upload", &EllipticsProxy::uploadHandler);
	registerHandler("delete", &EllipticsProxy::deleteHandler);
}

void
EllipticsProxy::onUnload() {
}

void
EllipticsProxy::pingHandler(fastcgi::Request *request) {
	if (elliptics_node_->state_num() < state_num_) {
		request->setStatus(500);
	}
	else {
		request->setStatus(200);
	}
}

void
EllipticsProxy::downloadInfoHandler(fastcgi::Request *request) {
        std::vector<int> groups_copy = groups_;
	std::vector<int>::iterator git = groups_copy.begin();
	++git;
	std::random_shuffle(git, groups_copy.end());
	elliptics_node_->add_groups(groups_copy);

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/download-info/") - 1, std::string::npos);

	try {
		std::string l = elliptics_node_->lookup(filename);

		std::string result = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

		const void *data = l.data();

		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		struct dnet_attr *attr = (struct dnet_attr *)(cmd + 1);
		struct dnet_addr_attr *a = (struct dnet_addr_attr *)(attr + 1);

		char hbuf[NI_MAXHOST];
		memset(hbuf, 0, NI_MAXHOST);

		if (getnameinfo((const sockaddr*)&a->addr, a->addr.addr_len, hbuf, sizeof (hbuf), NULL, 0, 0) != 0) {
			throw std::runtime_error("can not make dns lookup");
		}

		int port = dnet_server_convert_port((struct sockaddr *)a->addr.addr, a->addr.addr_len);

		char id[2 * DNET_ID_SIZE + 1];
		char hex_dir[2 * DNET_ID_SIZE + 1];

		struct dnet_id eid;
		elliptics_node_->transform(filename, eid);

		dnet_dump_id_len_raw(eid.id, DNET_ID_SIZE, id);
		file_backend_get_dir(eid.id, directory_bit_num_, hex_dir);

		std::pair<std::string, time_t> s = !use_cookie_ ? std::make_pair(std::string(), time(NULL)) : secret(request);

		std::ostringstream ostr;
		ostr << sign_key_ << std::hex << s.second << s.first;
		std::string sign = md5(ostr.str());

#ifdef HAVE_GEOBASE
		geobase3::v4::id geoid;
		try {
			std::string ip = request->hasHeader("X-Real-IP") ? request->getHeader("X-Real-IP") : request->getRemoteAddr();
			geoid = lookup_->region_id(ip);
		}
		catch (...) {
			geoid = -1;
		}
#endif

		char tsstr[32];
		snprintf(tsstr, sizeof (tsstr), "%lx", s.second);

		result += "<download-info><host>" + std::string(hbuf) + "</host>"
			"<path>/" + boost::lexical_cast<std::string>(port - base_port_) +
			'/' + hex_dir + '/' + id + "</path>" + "<ts>" + tsstr + "</ts>";
#ifdef HAVE_GEOBASE
		result += "<region>" + boost::lexical_cast<std::string>(geoid) + "</region>";
#endif
		result += "<s>" + sign + "</s></download-info>";

		request->setStatus(200);
		request->setContentType("text/xml");
		request->write(result.c_str(), result.length());
	}
	catch (const std::exception &e) {
		log()->error("can not get download info for file %s %s", filename.c_str(), e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("can not get download info for file %s", filename.c_str());
		request->setStatus(404);
	}
}

void
EllipticsProxy::getHandler(fastcgi::Request *request) {
	std::vector<int> groups_copy = groups_;
	std::vector<int>::iterator git = groups_copy.begin();
	++git;
	std::random_shuffle(git, groups_copy.end());
	elliptics_node_->add_groups(groups_copy);

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/get/") - 1, std::string::npos);

	std::string extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

	if (deny_list_.find(extention) != deny_list_.end() ||
		(deny_list_.find("*") != deny_list_.end() &&
		allow_list_.find(extention) == allow_list_.end())) {
		throw fastcgi::HttpException(403);
	}

	std::map<std::string, std::string>::iterator it = typemap_.find(extention);

	std::string content_type;
	if (typemap_.end() == it) {
		content_type = "application/octet";
	}
	else {
		content_type = it->second;
	}

	try {
		std::string result = elliptics_node_->read_data_wait(filename, 0);

		uint64_t ts = 0;
		if (request->hasArg("embed") || request->hasArg("embed_timestamp")) {
			size_t size = result.size();
			size_t offset = 0;

			while (size) {
				struct dnet_common_embed *e = (struct dnet_common_embed *)(result.data() + offset);

				dnet_common_convert_embedded(e);

				if (size < e->size + sizeof (struct dnet_common_embed)) {
					break;
				}

				if (e->type == DNET_FCGI_EMBED_TIMESTAMP) {
					uint64_t *ptr = (uint64_t *)e->data;

					ts = dnet_bswap64(ptr[0]);
				}

				offset += sizeof(struct dnet_common_embed);
				size -= sizeof(struct dnet_common_embed);

				if (e->type == DNET_FCGI_EMBED_DATA) {
					size = e->size;
					break;
				}

				offset += e->size;
				size -= e->size;
			}
			result = result.substr(offset, std::string::npos);
		}

		char ts_str[128];
		time_t timestamp = (time_t)(ts);
		struct tm tmp;
		strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %z", gmtime_r(&timestamp, &tmp));

		request->setStatus(200);
		request->setContentType(content_type);
		request->setHeader("Content-Length", boost::lexical_cast<std::string>(result.length()));
		request->setHeader("Last-Modified", ts_str);
		request->write(result.c_str(), result.size());
	}
	catch (const std::exception &e) {
		log()->error("can not locate file %s %s", filename.c_str(), e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("can not locate file %s", filename.c_str());
		request->setStatus(404);
	}
}

void
EllipticsProxy::statLogHandler(fastcgi::Request *request) {
	std::string result = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

	result += "<data>\n";

	std::string ret = elliptics_node_->stat_log();

	float la[3];
	const void *data = ret.data();
	int size = ret.size();
	char id_str[DNET_ID_SIZE * 2 + 1];
	char addr_str[128];

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		if (cmd->size != sizeof (struct dnet_attr) + sizeof (struct dnet_stat)) {
			size -= cmd->size + sizeof (struct dnet_addr) + sizeof (struct dnet_cmd);
			data = (char *)data + cmd->size + sizeof (struct dnet_addr) + sizeof (struct dnet_cmd);
			continue;
		}
		struct dnet_attr *attr = (struct dnet_attr *)(cmd + 1);
		struct dnet_stat *st = (struct dnet_stat *)(attr + 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		char buf[512];

		snprintf(buf, sizeof (buf), "<stat addr=\"%s\" id=\"%s\"><la>%.2f %.2f %.2f</la>"
			"<memtotal>%llu KB</memtotal><memfree>%llu KB</memfree><memcached>%llu KB</memcached>"
			"<storage_size>%llu MB</storage_size><available_size>%llu MB</available_size>"
			"<files>%llu</files><fsid>0x%llx</fsid></stat>",
			dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str)),
			dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str),
			la[0], la[1], la[2],
			(unsigned long long)st->vm_total,
			(unsigned long long)st->vm_free,
			(unsigned long long)st->vm_cached,
			(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
			(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
			(unsigned long long)st->files, (unsigned long long)st->fsid);

		result += buf;

		int sz = sizeof(*addr) + sizeof(*cmd) + sizeof(*attr) + attr->size;
		size -= sz;
		data = (char *)data + sz;
	}

	result += "</data>";

	request->setStatus(200);
	request->write(result.c_str(), result.size());
}

void
EllipticsProxy::uploadHandler(fastcgi::Request *request) {
	if (elliptics_node_->state_num() < state_num_) {
		request->setStatus(403);
		return;
	}

	bool embed = request->hasArg("embed") || request->hasArg("embed_timestamp");
	struct timespec ts;
	ts.tv_sec = request->hasArg("timestamp") ? boost::lexical_cast<uint64_t>(request->getArg("timestamp")) : 0;
	ts.tv_nsec = 0;

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/upload/") - 1, std::string::npos);

	fastcgi::DataBuffer buffer = request->requestBody();

	try {
		std::string content;
		if (embed) {
			int size = sizeof (struct dnet_common_embed) * 2 + sizeof (uint64_t) * 2;

			char header[size];
			int err = dnet_common_prepend_data(&ts, buffer.size(), header, &size);
			if (err != 0) {
				throw std::runtime_error("bad data prepending");
			}
			content.append(header, size);
		}

		content.reserve(content.size() + buffer.size());
		for (fastcgi::DataBuffer::SegmentIterator it = buffer.begin(), end = buffer.end(); it != end; ++it) {
			std::pair<char*, boost::uint64_t> chunk = *it;
			content.append(chunk.first, chunk.second);
		}

		struct dnet_id id;
		memset(&id, 0, sizeof (id));

		elliptics_node_->transform(filename, id);

		int result = elliptics_node_->write_data_wait(id, content);

		if (result == 0) {
			log()->error("can not write file %s", filename.c_str());
			request->setStatus(400);
			return;
		}

		request->setStatus(200);

		struct dnet_id row;
		char id_str[2 * DNET_ID_SIZE + 1];
		char crc_str[2 * DNET_ID_SIZE + 1];

		elliptics_node_->transform(content, row);
		dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, id_str);
		dnet_dump_id_len_raw(row.id, DNET_ID_SIZE, crc_str);

		std::ostringstream ostr;

		ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>" <<
			"<post obj=\"" << filename << "\" id=\"" << id_str <<
			"\" crc=\"" << crc_str << "\" groups=\"" << groups_.size() <<
			"\" size=\"" << content.length() << "\">\n";

		std::string lookup = elliptics_node_->lookup(filename);
		const void *data = lookup.data();

		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		struct dnet_attr *attr = (struct dnet_attr *)(cmd + 1);
		struct dnet_addr_attr *a = (struct dnet_addr_attr *)(attr + 1);

		int port = dnet_server_convert_port((struct sockaddr *)a->addr.addr, a->addr.addr_len);

		struct dnet_id eid;

		elliptics_node_->transform(filename, eid);

		char res_id[2 * DNET_ID_SIZE + 1];
		char hex_dir[2 * DNET_ID_SIZE + 1];

		dnet_dump_id_len_raw(eid.id, DNET_ID_SIZE, res_id);
		file_backend_get_dir(eid.id, directory_bit_num_, hex_dir);

		int err = cmd->status;

		std::size_t written = 0;
		for (std::size_t i = 0; i < groups_.size(); ++i) {
			std::string addr;
			try {
				addr = elliptics_node_->lookup_addr(filename, groups_[i]);
			}
			catch (...) {
				continue;
			}

			ostr << "<complete addr=\"" << addr << "\" path=\"/" <<
				boost::lexical_cast<std::string>(port - base_port_) <<
				'/' << hex_dir << '/' << res_id << "\" group=\"" << groups_[i] << "\" "
				"status=\"" << err << "\"/>\n";

			++written;
		}

		ostr << "<written>" << written << "</written>\n</post>";

		std::string response = ostr.str();

		if (written < success_copies_num_) {
			log()->error("can not write file %s %d copies instead %d", filename.c_str(), written, success_copies_num_);
			request->setStatus(403);
		}
		else {
			request->setStatus(200);
		}
		request->write(response.c_str(), response.length());
	}
	catch (const std::exception &e) {
		log()->error("can not write file %s %s", filename.c_str(), e.what());
		request->setStatus(400);
	}
	catch (...) {
		log()->error("can not write file %s", filename.c_str());
		request->setStatus(400);
	}
}

void
EllipticsProxy::deleteHandler(fastcgi::Request *request) {
	if (elliptics_node_->state_num() < state_num_) {
		request->setStatus(403);
		return;
	}

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/delete/") - 1, std::string::npos);

	try {
		elliptics_node_->remove(filename);
		request->setStatus(200);
	}
	catch (const std::exception &e) {
		log()->error("can not delete file %s %s", filename.c_str(), e.what());
		request->setStatus(400);
	}
	catch (...) {
		log()->error("can not write file %s", filename.c_str());
		request->setStatus(400);
	}
}

#ifdef HAVE_GEOBASE
void
EllipticsProxy::refresh() {
	struct stat st;
	int result = stat(filename_.c_str(), &st);

	if (result != 0) {
		log()->error("can not locate geobase file %s!", filename_.c_str());
		return;
	}

	if (st.st_mtime == last_modified_) {
		return;
	}

	last_modified_ = st.st_mtime;

	boost::shared_ptr<geobase3::lookup> clone_lookup(new geobase3::lookup(filename_.c_str()));

	boost::mutex::scoped_lock lock(mutex_);
	lookup_.swap(clone_lookup);
	lock.unlock();

	while (clone_lookup.get() && !clone_lookup.unique()) {
		usleep(1000);
	}
}
#endif

size_t
EllipticsProxy::paramsNum(Tokenizer &tok) {
	size_t result = 0;
	for (Tokenizer::iterator it = ++tok.begin(), end = tok.end(); end != it; ++it) {
		++result;
	}
	return result;
}

FCGIDAEMON_REGISTER_FACTORIES_BEGIN()
FCGIDAEMON_ADD_DEFAULT_FACTORY("elliptics-proxy", EllipticsProxy);
FCGIDAEMON_REGISTER_FACTORIES_END()

} // namespace elliptics

