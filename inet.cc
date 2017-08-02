#include <cmath>
#include <array>

#include "inet.hh"

constexpr std::array<char, 16> hex_key = { '0', '1', '2', '3', '4', '5', '6',
		'7', '8', '9', 'a', 'b', 'c', 'e', 'd', 'f' };

struct array_ipv6_ {
	typedef address_v6::bytes_type byte_type;
	static byte_type make_mask(uint64_t masklen) {
		byte_type mask { 0 };
		mask.fill(0xFF);
		for (size_t i = mask.size(); i > 0; i--, masklen -= 8) {
			if (masklen >= 8) {
				mask[i] = 0;
			} else {
				mask[i] &= (0xFF << masklen);
				break;
			}
		}
		if (masklen >= 8) {
			mask[0] = 0;
		} else {
			mask[0] &= (0xFF << masklen);
		}
		return mask;
	}
	static unsigned long get_masklen(const byte_type & mask) {
		unsigned long masklen = 0;
		for (size_t i = 0; mask.size(); i--) {
			if (mask[i] == 0xFF) {
				masklen += 8;
			} else {
				masklen += std::log2(mask[i]);
				break;
			}
		}
		return masklen;
	}
	static byte_type logic_and(const byte_type & lhs, const byte_type & rhs) {
		byte_type rtn = lhs;
		for (size_t i = 0; i < lhs.size(); i++) {
			rtn[i] &= rhs[i];
		}
		return rtn;
	}
	static bool smaller(const byte_type & lhs, const byte_type & rhs) {
		for (size_t i = 0; i < lhs.size(); i++) {
			if (lhs[i] != rhs[i]) {
				return lhs[i] < rhs[i];
			}
		}
		return false;
	}
};

ARPA::ARPA(const std::string & str) :
		arpa_(str) {
}

ARPA::ARPA(const INET & cidr) {
	if (cidr.is_ip4()) {
		auto addr = cidr.to_v4().to_bytes();
		std::reverse(addr.begin(), addr.end());
		arpa_ = address_v4(addr).to_string();
	} else {
		auto addr = cidr.to_v6().to_bytes();
		std::string str;
		for (auto b : addr) {
			str.insert(str.cbegin(), hex_key[(b & 0xF0) >> 4]);
			str.insert(str.cbegin(), '.');
			str.insert(str.cbegin(), hex_key[b & 0x0F]);
			str.insert(str.cbegin(), '.');
		}
		arpa_ = str.substr(1);
	}
}

std::string ARPA::to_ip_string() const {
	address_v4 addr_v4;
	boost::system::error_code ec;
	addr_v4 = address_v4::from_string(arpa_, ec);
	if (!ec) {
		auto addr = addr_v4.to_bytes();
		std::reverse(addr.begin(), addr.end());
		return address_v4(addr).to_string();
	} else {
		std::string str;
		int ctr = 0;
		for (auto i = arpa_.size() - 1; i > 0; i--) {
			if (arpa_[i] != '.') {
				str += arpa_[i];
				if (++ctr >= 4) {
					str += ':';
					ctr = 0;
				}
			}
		}
		str += arpa_[0];
		return address_v6::from_string(str).to_string();
	}
}

std::string ARPA::get() const {
	return arpa_;
}

constexpr unsigned long get_ipv4_bradcast() {
	return 0xFFFFFFFF;
}

inline void INET::set_ip4_(const address_v4 & ip, uint64_t masklen) {
	type_ = ipv4;
	ipv4_address_ = ip;
	masklen_ = masklen;
	init_mask_(masklen_);
}

inline void INET::set_ip6_(const address_v6 & ip, uint64_t masklen) {
	type_ = ipv6;
	ipv6_address_ = ip;
	masklen_ = masklen;
	init_mask_(masklen_);
}

void INET::set_equal_to_(const INET & other) {
	ipv4_address_ = other.ipv4_address_;
	ipv4_mask_ = other.ipv4_mask_;
	ipv6_address_ = other.ipv6_address_;
	ipv6_mask_ = other.ipv6_mask_;
	masklen_ = other.masklen_;
	type_ = other.type_;
}

void INET::set_equal_to_(const address & ip) {
	if (ip.is_v4()) {
		set_equal_to_(ip.to_v4());
	} else {
		set_equal_to_(ip.to_v6());
	}
}

void INET::set_equal_to_(const address_v4 & ip) {
	set_ip4_(ip);
	ipv4_mask_ = get_ipv4_bradcast();
}

void INET::set_equal_to_(const address_v6 & ip) {
	set_ip6_(ip);
	ipv6_mask_ = array_ipv6_::make_mask(masklen_);
}

void INET::set_equal_to_(const std::string & str) {
	auto it = str.find('/');
	if (it != str.npos) {
		address ip = address::from_string(str.substr(0, it));
		set_equal_to_(ip);
		masklen_ = std::stoull(str.substr(it + 1));
		init_mask_(masklen_);
	} else {
		address ip = address::from_string(str);
		set_equal_to_(ip);
	}
}

void INET::set_equal_to_(const ARPA & arpa) {
	set_equal_to_(arpa.to_ip_string());
}

void INET::init_mask_(uint64_t masklen) {
	if (type_ == ipv4) {
		if (masklen > 32) {
			throw std::length_error("IPV4 with mask length > 32");
		}
		ipv4_mask_ = get_ipv4_bradcast();
		ipv4_mask_ <<= 32 - masklen;
		ipv4_mask_ &= get_ipv4_bradcast();
	} else {
		if (masklen > 128) {
			throw std::length_error("IPV6 with mask length > 128");
		}
		ipv6_mask_ = array_ipv6_::make_mask(masklen);
	}
}

INET::INET(const std::string &str) {
	set_equal_to_(str);
}

INET::INET(const ARPA &arpa) {
	set_equal_to_(arpa);
}

INET::INET(const address & ip, uint64_t masklen) {
	set_equal_to_(ip);
	masklen_ = masklen;
	init_mask_(masklen_);
}

INET::INET(const address_v4 & ip, uint64_t masklen) {
	set_equal_to_(ip);
	masklen_ = masklen;
	init_mask_(masklen_);
}

INET::INET(const address_v6 & ip, uint64_t masklen) {
	set_equal_to_(ip);
	masklen_ = masklen;
	init_mask_(masklen_);
}

INET::INET(const INET &other) {
	set_equal_to_(other);
}

INET & INET::operator=(const INET & other) {
	set_equal_to_(other);
	return *this;
}

// cc1plus: warning: ‘void* __builtin_memset(void*, int, long unsigned int)’ writing 16 bytes into a region of size 15 overflows the destination [-Wstringop-overflow=]
INET & INET::operator=(const address & ip) {
	set_equal_to_(ip);
	return *this;
}

INET & INET::operator=(const address_v4 & ip) {
	set_equal_to_(ip);
	return *this;
}

INET & INET::operator=(const address_v6 & ip) {
	set_equal_to_(ip);
	return *this;
}

INET & INET::operator=(const std::string & str) {
	set_equal_to_(str);
	return *this;
}

INET & INET::operator=(const ARPA & arpa) {
	set_equal_to_(arpa);
	return *this;
}

std::string INET::to_string(bool show_mask) const {
	std::string mask = show_mask ? '/' + std::to_string(masklen_) : "";
	if (type_ == ipv4) {
		return ipv4_address_.to_string() + mask;
	}
	return ipv6_address_.to_string() + mask;
}

std::string INET::to_arpa() const {
	return ARPA(*this).get();
}

uint64_t INET::get_subnet() const {
	return masklen_;
}

void INET::set_subnet(uint64_t masklen) {
	init_mask_(masklen);
	masklen_ = masklen;
}

std::string INET::get_subnet_string() const {
	if (type_ == ipv4) {
		return address_v4(ipv4_mask_).to_string();
	} else {
		return address_v6(ipv6_mask_).to_string();
	}
}

void INET::set_subnet_string(const std::string &str) {
	address mask = address::from_string(str);
	if (mask.is_v4()) {
		ipv4_mask_ = mask.to_v4().to_ulong();
		masklen_ = std::log2(ipv4_mask_);
	} else {
		ipv6_mask_ = mask.to_v6().to_bytes();
		masklen_ = array_ipv6_::get_masklen(ipv6_mask_);
	}
}

bool INET::operator==(const INET & other) const {
	if (type_ != other.type_ || masklen_ != other.masklen_) {
		return false;
	}
	if (type_ == ipv4) {
		return ipv4_address_ == other.ipv4_address_;
	} else {
		return ipv6_address_ == other.ipv6_address_;
	}
}

bool INET::operator!=(const INET & other) const {
	return !(*this == other);
}

bool INET::operator<(const INET & other) const {
	if (type_ != other.type_) {
		return type_ < other.type_;
	}
	if (masklen_ != other.masklen_) {
		return masklen_ > other.masklen_;
	}
	if (type_ == ipv4) {
		return ipv4_address_.to_ulong() < other.ipv4_address_.to_ulong();
	} else {
		return array_ipv6_::smaller(ipv6_address_.to_bytes(),
				other.ipv6_address_.to_bytes());
	}
}

bool INET::operator<=(const INET & other) const {
	return !(*this > other);
}

bool INET::operator>(const INET & other) const {
	return (*this < other);
}

bool INET::operator>=(const INET & other) const {
	return !(*this < other);
}

bool INET::operator<<(const INET & other) const {
	if (masklen_ < other.masklen_) {
		return *this <<= other;
	}
	return false;
}

bool INET::operator<<=(const INET & other) const {
	if (type_ != other.type_) {
		return false;
	}
	if (masklen_ <= other.masklen_) {
		if (type_ == ipv4) {
			return (ipv4_address_.to_ulong() & other.ipv4_mask_)
					== (other.ipv4_address_.to_ulong() & other.ipv4_mask_);
		}
		return array_ipv6_::logic_and(ipv6_address_.to_bytes(),
				other.ipv6_mask_)
				== array_ipv6_::logic_and(other.ipv6_address_.to_bytes(),
						other.ipv6_mask_);
	}
	return false;
}

bool INET::operator>>(const INET & other) const {
	return other << *this;
}

bool INET::operator>>=(const INET & other) const {
	return other <<= *this;
}

address_v4 INET::to_v4() const {
	if (type_ == ipv4) {
		return ipv4_address_;
	}
	throw std::bad_cast();
}

address_v6 INET::to_v6() const {
	if (type_ == ipv6) {
		return ipv6_address_;
	}
	throw std::bad_cast();
}

INET::Type INET::get_type() const {
	return type_;
}

bool INET::is_ip4() const {
	return type_ == ipv4;
}

bool INET::is_ip6() const {
	return type_ == ipv6;
}

std::string to_ipv4_string(uint32_t ip) {
	return std::to_string(ip >> 24) + "."
			+ std::to_string((ip & 0xFF0000) >> 16) + "."
			+ std::to_string((ip & 0xFF00) >> 8) + "."
			+ std::to_string(ip & 0xFF);
}
