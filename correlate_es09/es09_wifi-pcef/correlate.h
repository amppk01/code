#define MAX_CORR    4096

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "rds.h"
#include "rds_dict.h"
#include "base64.h"
#include "sflib.h"
#include "sflog.h"


struct _rds_code_
{
	int code;
	int flag;
	char name[1];   /* must be the last */
};
struct _rds_vendor_
{
	int code;
	int attr_count;
	int attr_size;
	struct _rds_attr_ **attr_by_time;
	struct _rds_attr_ **attr_by_name;
	struct _rds_attr_ **attr_by_code;
	char name[1];   /* must be the last */
};

struct _rds_attr_
{
	struct _rds_vendor_ *vendor;
	int code;
	int type;
	/* tlv */
	struct _rds_attr_ *attr;
	int tlv_count;
	int tlv_size;
	struct _rds_attr_ **tlv_attr_by_time;
	struct _rds_attr_ **tlv_attr_by_name;
	struct _rds_attr_ **tlv_attr_by_code;
	/* value */
	int value_count;
	int value_size;
	struct _rds_value_ **value_by_time;
	struct _rds_value_ **value_by_name;
	struct _rds_value_ **value_by_code;
	char name[1];   /* must be the last */
};
struct _rds_value_
{
	struct _rds_attr_ *attr;
	int code;
	char name[1];   /* must be the last */
};
struct _rds_dict_
{
	int code_count;
	int code_size;
	struct _rds_code_ **code_by_time;
	struct _rds_code_ **code_by_name;
	struct _rds_code_ **code_by_code;

	int vendor_count;
	int vendor_size;
	struct _rds_vendor_ **vendor_by_time;
	struct _rds_vendor_ **vendor_by_name;
	struct _rds_vendor_ **vendor_by_code;
};

typedef struct _rds_dict_ RDS_DICT;
typedef struct _rds_vendor_ RDS_DICT_VENDOR;
typedef struct _rds_attr_ RDS_DICT_ATTR;


#if defined(BIN_TO_HEX)

#define _RDT_BIN_TO_TEXT(_data,_dlen,_buff,_blen)   _rds_hex_encode((_data),(_dlen),(_buff),(_blen))
#define _RDT_TEXT_BUFFER_SIZE                       ((2*RDS_MAX_MESSAGE_LENGTH)+1)
#define _RDT_TEXT_TO_BIN(_data,_dlen,_buff,_blen)   _rds_hex_decode((_data),(_dlen),(_buff),(_blen))

#else

#define _RDT_BIN_TO_TEXT(_data,_dlen,_buff,_blen)   _rds_base64_encode((_data),(_dlen),(_buff),(_blen))
#define _RDT_TEXT_BUFFER_SIZE                       (BASE64_ENCODE_SIZE(RDS_MAX_MESSAGE_LENGTH)+1)
#define _RDT_TEXT_TO_BIN(_data,_dlen,_buff,_blen)   _rds_base64_decode((_data),(_dlen),(_buff),(_blen))

#endif

#define _RDT_UCHAR_POINTER(_base,_offset)           ((unsigned char *)(_base))[(_offset)]
#define _RDT_FETCH_UCHAR(_base,_offset)             (               _RDT_UCHAR_POINTER((_base),(_offset)) )
#define _RDT_FETCH_UCHAR_AS_INT(_base,_offset)      (          (int)_RDT_UCHAR_POINTER((_base),(_offset)) )
#define _RDT_FETCH_UCHAR_AS_UINT(_base,_offset)     ( (unsigned int)_RDT_UCHAR_POINTER((_base),(_offset)) )
#define _RDT_FETCH_USHORT(_base,_offset)            ( (_RDT_FETCH_UCHAR_AS_UINT((_base),(_offset))  <<8)  |  _RDT_FETCH_UCHAR_AS_INT ((_base),(_offset)+1)        )
#define _RDT_FETCH_INT32(_base,_offset)             ( (_RDT_FETCH_UCHAR_AS_INT ((_base),(_offset))  <<24) | (_RDT_FETCH_UCHAR_AS_INT ((_base),(_offset)+1)<<16) | \
                                                      (_RDT_FETCH_UCHAR_AS_INT ((_base),(_offset)+2)<<8)  |  _RDT_FETCH_UCHAR_AS_UINT((_base),(_offset)+3)        )
#define _RDT_FETCH_UINT32(_base,_offset)            ( (_RDT_FETCH_UCHAR_AS_UINT((_base),(_offset))  <<24) | (_RDT_FETCH_UCHAR_AS_UINT((_base),(_offset)+1)<<16) | \
                                                      (_RDT_FETCH_UCHAR_AS_UINT((_base),(_offset)+2)<<8)  |  _RDT_FETCH_UCHAR_AS_UINT((_base),(_offset)+3)        )

#define _RDS_BINARY_SEARCH_BY_CODE(_code,_array,_count,_last,_res)   \
{                                                                    \
   int i_, j_, k_, r_;                                               \
   i_ = 0;                                                           \
   j_ = (_count) - 1;                                                \
   k_ = i_;                                                          \
   r_ = -1;                                                          \
            while (i_ <= j_)                                                  \
					 	     {                                                                 \
      k_ = (i_ + j_) / 2;                                            \
      r_ = (_code) - ((_array)[k_])->code;                           \
      if (r_ == 0)                                                   \
         break;                                                      \
      if (r_ < 0)                                                    \
         j_ = k_ - 1;                                                \
										        else                                                           \
         i_ = k_ + 1;                                                \
					 	     }                                                                 \
   (_last) = k_;                                                     \
   (_res) = r_;                                                      \
}

//#define STR_ATTR_VENDOR              "vendor"
//#define STR_ATTR_VENDOR_ID           "id"
//#define STR_ATTR_CODE                "code"
//#define STR_ATTR_VALUE_DATA          "value"

#define STR_ATTR_VENDOR              1
#define STR_ATTR_VENDOR_ID           2
#define STR_ATTR_CODE                3
#define STR_ATTR_VALUE_DATA          4

void on_element_attrib(char * elename, int attrib_t, char * attrib_val);
void on_element_attrib_uint(char * elename, int attrib_t, uint attrib_val);

static char global_cor[MAX_CORR];

static char *
_rds_hex_encode(char *data, int len, char *out, int olen)
{
	char *o = out;
	static char hex[] = "0123456789ABCDEF";

	--olen;   /* reserve for null character */
	while (len > 0)
	{
		olen -= 2;
		if (olen < 0)
			return "*";
		*out++ = hex[(*data >> 4) & 0x0F];
		*out++ = hex[*data & 0x0F];
		++data;
		--len;
	}
	*out = '\0';
	return o;
}

static char *
_rds_base64_encode(char *data, int len, char *b64, int blen)
{
	char *bb = b64;

	if (len > 0)
	{
		base64_encode(&data, &len, &b64, &blen);
		if (len > 0)
			return "";
	}
	if (blen <= 0)
		return "";
	*b64 = '\0';
	return bb;
}


static int
rds_data_type_decode(int vtype, char *data, int len, char *buffer, int blen, char *err_str)
{
	int n;
	RDS_OS_ERR_BUFFER

		switch (vtype)
	{
		/*
		Value type from RFC 2865

		text      1-253 octets containing UTF-8 encoded 10646 [7]
		characters.  Text of length zero (0) MUST NOT be sent;
		omit the entire attribute instead.
		string    1-253 octets containing binary data (values 0 through
		255 decimal, inclusive).  Strings of length zero (0)
		MUST NOT be sent; omit the entire attribute instead.
		address   32 bit value, most significant octet first.
		integer   32 bit unsigned value, most significant octet first.
		time      32 bit unsigned value, most significant octet first --
		seconds since 00:00:00 UTC, January 1, 1970.  The
		standard Attributes do not use this data type but it is
		presented here for possible use in future attributes.
		*/
		case RDS_VALUE_TYPE_TEXT:
			if (len < 1 || len > 253)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of text attribute (%d), must be 1-253", len);
				return -1;
			}
			if (len >= blen)
			{
				if (err_str != NULL)
					sprintf(err_str, "Buffer is too small (%d), must be at lease (%d)", blen, len + 1);
				return -1;
			}
			n = 0;
			while (n < len && data[n])
				++n;
			if (n < len)
			{
				if (err_str != NULL)
					sprintf(err_str, "Text attribute can not contains null, must be UTF-8");
				return -1;
			}
			memcpy(buffer, data, len);
			buffer[len] = '\0';
			break;
		case RDS_VALUE_TYPE_STRING:
			if (len < 0 || len > 253)   /* allow zero length, even conflict with RFC 2865 */
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of string (binary) attribute (%d), must be 1-253", len);
				return -1;
			}
			if ((2 * len + 3) >= blen) // including "0x"
			{
				if (err_str != NULL)
					sprintf(err_str, "Buffer is too small (%d), must be at lease (%d)", blen, 2 * len + 3);
				return -1;
			}
			buffer[0] = '0'; buffer[1] = 'x';
			_rds_hex_encode(data, len, buffer + 2, blen - 2);
			buffer[2 * len + 2] = '\0';
			break;
		case RDS_VALUE_TYPE_IPV4ADDR:
			if (len != 4)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of ip4 attribute (%d), must be 4", len);
				return -1;
			}
		ipv4_format:
			if (blen < (4 * (3 + 1)))
			{
				if (err_str != NULL)
					sprintf(err_str, "Buffer is too small (%d), must be at lease (%d)", blen, (4 * (3 + 1)));
				return -1;
			}
			sprintf(buffer, "%d.%d.%d.%d", _RDT_FETCH_UCHAR(data, 0), _RDT_FETCH_UCHAR(data, 1), _RDT_FETCH_UCHAR(data, 2), _RDT_FETCH_UCHAR(data, 3));
			break;
		case RDS_VALUE_TYPE_INTEGER:
			if (len != 4)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of integer32 attribute (%d), must be 4", len);
				return -1;
			}
			if (blen < (10 + 1))   /* 32 bits equal 10 digits */
			{
				if (err_str != NULL)
					sprintf(err_str, "Buffer is too small (%d), must be at lease (%d)", blen, (10 + 1));
				return -1;
			}
			sprintf(buffer, "%u", _RDT_FETCH_UINT32(data, 0));
			break;
		case RDS_VALUE_TYPE_TIME:
			if (len != 4)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of time attribute (%d), must be 4", len);
				return -1;
			}
			if (blen < (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1))   /* yyyy-mm-dd hh:mm:ss */
			{
				if (err_str != NULL)
					sprintf(err_str, "Buffer is too small (%d), must be at lease (%d)", blen, (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1));
				return -1;
			}
			{
#if defined(OS_WINDOWS)
				int er;
				struct tm tm;
				__time32_t ct = _RDT_FETCH_UINT32(data, 0);
				er = _gmtime32_s(&tm, &ct);
				if (er)
				{
					if (err_str != NULL)
						sprintf(err_str, "_gmtime32_s (0x%lX) return error [%s]", (unsigned long)ct, strerror(er));
					return -1;
				}
#else
				time_t ct = _RDT_FETCH_UINT32(data, 0);
				struct tm tm;
				if (gmtime_r(&ct, &tm) == NULL)
				{
					if (err_str != NULL)
						sprintf(err_str, "gmtime_r (0x%lX) return error [%s]", (unsigned long)ct, RDS_OS_ERROR_STRING);
					return -1;
				}
#endif
				sprintf(buffer, "%04u-%02u-%02u %02u:%02u:%02u", tm.tm_year + 1900, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
			}
			break;

			/*
			Value type from RFC 3162
			*/
		case RDS_VALUE_TYPE_IPV6ADDR:
			/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|     Type      |    Length     |             Address
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Address
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Address
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Address
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Address             |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			*/
			if (len != 16)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of IPv6 attribute (%d), must be 16", len);
				return -1;
			}
		ipv6_format:
#if defined(OS_WINDOWS)
			{
				struct sockaddr_in6 in;
				memset(&in, 0, sizeof(in));
				in.sin6_family = AF_INET6;
				memcpy(&in.sin6_addr, data, sizeof(struct in_addr6));
				if (getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), buffer, blen, NULL, 0, NI_NUMERICHOST) != 0)
				{
					if (err_str != NULL)
						sprintf(err_str, "getnameinfo return error [%s]", RDS_OS_ERROR_STRING);
					return -1;
				}
			}
#else
			if (inet_ntop(AF_INET6, data, buffer, blen) == NULL)
			{
				if (err_str != NULL)
					sprintf(err_str, "inet_ntop return error [%s]", RDS_OS_ERROR_STRING);
				return -1;
			}
#endif
			break;
		case RDS_VALUE_TYPE_IPV6PREFIX:
			/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|     Type      |    Length     |  Reserved     | Prefix-Length |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Prefix
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Prefix
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Prefix
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Prefix                             |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			*/
			if (len < 2 || len > 18)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of IPv6-Prefix attribute (%d), must be between 2 to 16", len);
				return -1;
			}
			if (_RDT_FETCH_UCHAR(data, 0) != 0)
			{
				if (err_str != NULL)
					sprintf(err_str, "Reserved (%d) of IPv6-Prefix attribute must be zero", _RDT_FETCH_UCHAR(data, 0));
				return -1;
			}
			if (_RDT_FETCH_UCHAR(data, 1) > 128)
			{
				if (err_str != NULL)
					sprintf(err_str, "Prefix-Length (%d) of IPv6-Prefix attribute must not larger than 128", _RDT_FETCH_UCHAR(data, 1));
				return -1;
			}
			_RDT_BIN_TO_TEXT(data, len, buffer, blen);
			break;
		case RDS_VALUE_TYPE_IFID:
			/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|     Type      |    Length     |             Interface-Id
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Interface-Id
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Interface-Id             |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			*/
			if (len != 8)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of Interface-Id attribute (%d), must be between 8", len);
				return -1;
			}
			_RDT_BIN_TO_TEXT(data, len, buffer, blen);
			break;
			/*
			Value type from RFC 5904
			From freeradius dictionary.wimax
			#       short    - two-octet unsigned integer in network byte order
			*/
		case RDS_VALUE_TYPE_SHORT:
			if (len != 2)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of short attribute (%d), must be between 8", len);
				return -1;
			}
			sprintf(buffer, "%u", _RDT_FETCH_USHORT(data, 0));
			break;
			/*
			WIMAX
			combo-ip - if length 4, is the same as the "ipaddr" type.
			if length 16, is the same as "ipv6addr" type.
			tlv      - encapsulated sub-attributes
			i.e. Vendor-Specific -> WiMAX TLV -> WiMAX sub-tlv.
			*/
		case RDS_VALUE_TYPE_COMBOIP:
			if (len == 4)
				goto ipv4_format;
			if (len == 16)
				goto ipv6_format;
			if (err_str != NULL)
				sprintf(err_str, "Invalid length of combo-ip attribute (%d), must be 4 or 16", len);
			return -1;
			break;
		case RDS_VALUE_TYPE_GROUPED:   /* tlv */
			if (err_str != NULL)
				sprintf(err_str, "Invalid tlv attribute value type");
			return -1;
			/*
			Others
			*/
		case RDS_VALUE_TYPE_BYTE:
			if (len != 1)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of byte attribute (%d), must be 1", len);
				return -1;
			}
			sprintf(buffer, "%u", _RDT_FETCH_USHORT(data, 0));
			break;
		case RDS_VALUE_TYPE_SIGNED:
			if (len != 4)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of signed attribute (%d), must be 4", len);
				return -1;
			}
			sprintf(buffer, "%d", _RDT_FETCH_INT32(data, 0));
			break;
		case RDS_VALUE_TYPE_MAC:
			if (len != 6)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid length of MAC attribute (%d), must be 6", len);
				return -1;
			}
			if (blen < (2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1))   /* x:x:x:x:x:x */
			{
				if (err_str != NULL)
					sprintf(err_str, "Buffer is too small (%d), must be at lease (%d)", blen, 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1);
				return -1;
			}
			sprintf(buffer, "%x:%x:%x:%x:%x:%x", _RDT_FETCH_UCHAR(data, 0), _RDT_FETCH_UCHAR(data, 1), _RDT_FETCH_UCHAR(data, 2), _RDT_FETCH_UCHAR(data, 3), _RDT_FETCH_UCHAR(data, 4), _RDT_FETCH_UCHAR(data, 5));
			break;
		default:
			if (err_str != NULL)
				sprintf(err_str, "Unknown attribute value type (%d)", vtype);
			return -1;

	}

	return 0;
}


int
rds_dict_get_attr_by_code(RDS_DICT *rds, RDS_DICT_VENDOR *vendor, int code, char **name, int *type, RDS_DICT_ATTR **attr, char *err_str)
{
	int last, r;

	_RDS_BINARY_SEARCH_BY_CODE(code, vendor->attr_by_code, vendor->attr_count, last, r)
		if (r != 0)
		{
		if (err_str != NULL)
			sprintf(err_str, "ATTRIBUTE-CODE (%d) not found", code);
		return RDS_DICT_RET_ERROR;
		}
	if (name != NULL)
		*name = vendor->attr_by_code[last]->name;
	if (type != NULL)
		*type = vendor->attr_by_code[last]->type;
	if (attr != NULL)
		*attr = vendor->attr_by_code[last];
	return RDS_DICT_RET_OK;
}


int
rds_dict_get_attr_code(RDS_DICT_ATTR *attr)
{
	return attr->code;
}

static int
_rds_data_dispatch(RDS_DICT *dict, RDS_DICT_VENDOR *vendor, RDS_DICT_ATTR *sattr, char *data, int len, int verbose, char *text_buff, char *err_str)
{
	char *aname;
	int atype, alen, vid, vtype;
	RDS_DICT_ATTR *sa = NULL;
	RDS_DICT_VENDOR *vd = NULL;
	/*
	Attribute
	0                   1                   2
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	|     Type      |    Length     |  String ...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	*/
	while (len > 0)
	{
		if (len < 2)   /* allow zero length, even conflict with RFC 2865 */
		{
			if (err_str != NULL)
				sprintf(err_str, "Invalid attribute format");
			return -1;
		}

		atype = _RDT_FETCH_UCHAR(data, 0);
		alen = _RDT_FETCH_UCHAR(data, 1);
		if (len < alen)
		{
			if (err_str != NULL)
				sprintf(err_str, "Invalid attribute format");
			return -1;
		}

		if (sattr != NULL)
		{
			if (rds_dict_get_sub_attr_by_code(dict, sattr, atype, &aname, &vtype, &sa, err_str) != 0)
				return -1;
		}
		else
		{
			if (rds_dict_get_attr_by_code(dict, vendor, atype, &aname, &vtype, &sa, err_str) != 0)
				return -1;
		}

		if (atype == RDS_ATTR_VENDOR_SPECIFIC_TYPE && rds_dict_get_vendor_code(vendor) == RDS_DEFAULT_VENDOR_CODE)
		{
			/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|     Type      |  Length       |            Vendor-Id
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Vendor-Id (cont)           |  String...
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			*/
			if (alen <= (1 + 1 + 4))
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid \"Vendor-Specific\" attribute format");
				return -1;
			}
			/*
			The high-order octet is 0 and the low-order 3 octets are the SMI
			Network Management Private Enterprise Code of the Vendor in
			network byte order, as defined in the "Assigned Numbers" RFC 1700
			*/
			if (_RDT_FETCH_UCHAR(data, 2) != 0)
			{
				if (err_str != NULL)
				{
					sprintf(err_str, "Invalid \"Vendor-Id\" attribute {%02X,%02X,%02X,%02X}, first byte must be zero",
						_RDT_FETCH_UCHAR(data, 1 + 1),
						_RDT_FETCH_UCHAR(data, 1 + 1 + 1),
						_RDT_FETCH_UCHAR(data, 1 + 1 + 2),
						_RDT_FETCH_UCHAR(data, 1 + 1 + 3)
						);
				}
				return -1;
			}
			vid = _RDT_FETCH_INT32(data, 2);
			if (rds_dict_get_vendor_by_code(dict, vid, NULL, &vd, err_str) != 0)
			{
				if (err_str != NULL)
					sprintf(err_str, "Invalid \"Vendor-Specific\" attribute format");
				return -1;
			}

			if (verbose)
			{
				on_element_attrib(aname, STR_ATTR_VENDOR, rds_dict_get_vendor_name(vd));
				on_element_attrib_uint(aname, STR_ATTR_VENDOR, atype);
			}
			//!-_RDTSE_ADD_ATTR_UINT(el, STR_ATTR_VALUE_DATA, vid)
			//SFLOG_DEBUG("VSA[%s][%d][%s][%d][%s]", aname, atype, rds_type_to_string_tab[vtype], alen, rds_dict_get_vendor_name(vd))
			if (_rds_data_dispatch(dict, vd, NULL, data + 1 + 1 + 4, alen - 1 - 1 - 4, verbose, text_buff, err_str) != 0)
				return -1;

			data += alen;
			len -= alen;
			continue;
		}

		/* Attributes */
		if (verbose)
		{
			on_element_attrib_uint(aname, STR_ATTR_CODE, atype);
		}

		if (rds_dict_get_attr_type(sa) == RDS_VALUE_TYPE_GROUPED)
		{
			if (_rds_data_dispatch(dict, vendor, sa, data + 1 + 1, len - 1 - 1, verbose, text_buff, err_str) != 0)
				return -1;
		}
		else
		{
			if (rds_data_type_decode(vtype, data + 1 + 1, alen - 1 - 1, text_buff, _RDT_TEXT_BUFFER_SIZE, err_str) != 0)
				return -1;
			on_element_attrib(aname, STR_ATTR_VENDOR, text_buff);
		}
		//SFLOG_DEBUG("AVP[%s][%d][%s][%d][%s]", aname, atype, rds_type_to_string_tab[vtype], alen, text_buff)

		data += alen;
		len -= alen;

	}
	return 0;
}


int
rds_data_dispatch(RDS_DICT *dict, RDS_DICT_VENDOR *vendor, char *secret, char *data, int dlen, struct sockaddr_in *addr, int verbose, char *err_str)
{
	char text_buff[_RDT_TEXT_BUFFER_SIZE];
	if (secret != NULL)
	{
		SFLOG_DEBUG("secret %s", secret);
		int slen = (int)(2 * strlen(secret));
		text_buff[0] = '0'; text_buff[1] = 'x';
		_rds_hex_encode(secret, (int)strlen(secret), text_buff + 2, _RDT_TEXT_BUFFER_SIZE - 2);
		_rds_hex_encode(data + RDS_AUTHEN_OFFSET, RDS_AUTHEN_SIZE, text_buff + slen + 2, _RDT_TEXT_BUFFER_SIZE - slen - 2);
		text_buff[slen + (2 * RDS_AUTHEN_SIZE) + 2] = '\0';
	}

	if (vendor == NULL)
	{
		if (rds_dict_get_vendor_by_code(dict, RDS_DEFAULT_VENDOR_CODE, NULL, &vendor, err_str) != 0)
			return RDS_RET_ERROR;
	}
	data += RDS_AUTHEN_OFFSET + RDS_AUTHEN_SIZE;
	dlen -= RDS_AUTHEN_OFFSET + RDS_AUTHEN_SIZE;

	SFLOG_DEBUG("data len %d", dlen);
	if (_rds_data_dispatch(dict, vendor, NULL, data, dlen, verbose, text_buff, err_str) != 0)
		return RDS_RET_ERROR;

	return RDS_RET_OK;
}


int extract_correlate(RDS_DICT * dict, char * secret, RDS_MSG * msg, char* corr, int max_output);
