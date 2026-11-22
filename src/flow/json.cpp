#include "flow/json.h"

#include <charconv>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace flow {

bool Json::truthy() const {
    switch (t_) {
        case NUL: return false;
        case BOOL:
        case INT: return i_ != 0;
        case DBL: return d_ != 0;
        case STR: return !s_.empty();
        case ARR: return !a_.empty();
        case OBJ: return !keys_.empty();
    }
    return false;
}

const Json* Json::get(std::string_view k) const {
    if (t_ != OBJ) return nullptr;
    auto it = idx_.find(k);
    return it == idx_.end() ? nullptr : &a_[it->second];
}

Json& Json::operator[](const std::string& k) {
    if (t_ == NUL) t_ = OBJ;
    auto it = idx_.find(k);
    if (it != idx_.end()) return a_[it->second];
    idx_.emplace(k, a_.size());
    keys_.push_back(k);
    a_.emplace_back();
    return a_.back();
}

void Json::erase(std::string_view k) {
    auto it = idx_.find(k);
    if (it == idx_.end()) return;
    const size_t at = it->second;
    a_.erase(a_.begin() + static_cast<std::ptrdiff_t>(at));
    keys_.erase(keys_.begin() + static_cast<std::ptrdiff_t>(at));
    idx_.clear();
    for (size_t i = 0; i < keys_.size(); ++i) idx_.emplace(keys_[i], i);
}

namespace {

struct Parser {
    std::string_view s;
    size_t p = 0;

    [[noreturn]] void fail(const char* what) {
        throw std::runtime_error(std::string("JSON: ") + what + " at offset " + std::to_string(p));
    }
    void ws() {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\n' || s[p] == '\r' || s[p] == '\t')) ++p;
    }
    static void utf8(std::string& o, uint32_t c) {
        if (c < 0x80) {
            o += static_cast<char>(c);
        } else if (c < 0x800) {
            o += static_cast<char>(0xC0 | (c >> 6));
            o += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            o += static_cast<char>(0xE0 | (c >> 12));
            o += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            o += static_cast<char>(0xF0 | (c >> 18));
            o += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            o += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    uint32_t hex4() {
        if (p + 4 > s.size()) fail("bad escape");
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = s[p++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else fail("bad escape");
        }
        return v;
    }
    std::string str() {
        if (s[p] != '"') fail("expected string");
        ++p;
        std::string o;
        while (true) {
            if (p >= s.size()) fail("unterminated string");
            const char c = s[p++];
            if (c == '"') break;
            if (c != '\\') {
                o += c;
                continue;
            }
            if (p >= s.size()) fail("bad escape");
            const char e = s[p++];
            switch (e) {
                case '"': o += '"'; break;
                case '\\': o += '\\'; break;
                case '/': o += '/'; break;
                case 'b': o += '\b'; break;
                case 'f': o += '\f'; break;
                case 'n': o += '\n'; break;
                case 'r': o += '\r'; break;
                case 't': o += '\t'; break;
                case 'u': {
                    uint32_t c1 = hex4();
                    if (c1 >= 0xD800 && c1 < 0xDC00 && p + 6 <= s.size() && s[p] == '\\' && s[p + 1] == 'u') {
                        p += 2;
                        const uint32_t c2 = hex4();
                        c1 = 0x10000 + ((c1 - 0xD800) << 10) + (c2 - 0xDC00);
                    }
                    utf8(o, c1);
                    break;
                }
                default: fail("bad escape");
            }
        }
        return o;
    }
    Json value() {
        ws();
        if (p >= s.size()) fail("unexpected end");
        const char c = s[p];
        if (c == '{') {
            ++p;
            Json o = Json::object();
            ws();
            if (p < s.size() && s[p] == '}') {
                ++p;
                return o;
            }
            while (true) {
                ws();
                std::string k = str();
                ws();
                if (p >= s.size() || s[p] != ':') fail("expected ':'");
                ++p;
                o[k] = value();
                ws();
                if (p < s.size() && s[p] == ',') {
                    ++p;
                    continue;
                }
                if (p < s.size() && s[p] == '}') {
                    ++p;
                    return o;
                }
                fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            ++p;
            Json a = Json::array();
            ws();
            if (p < s.size() && s[p] == ']') {
                ++p;
                return a;
            }
            while (true) {
                a.push(value());
                ws();
                if (p < s.size() && s[p] == ',') {
                    ++p;
                    continue;
                }
                if (p < s.size() && s[p] == ']') {
                    ++p;
                    return a;
                }
                fail("expected ',' or ']'");
            }
        }
        if (c == '"') return Json(str());
        if (s.substr(p, 4) == "true") {
            p += 4;
            return Json(true);
        }
        if (s.substr(p, 5) == "false") {
            p += 5;
            return Json(false);
        }
        if (s.substr(p, 4) == "null") {
            p += 4;
            return Json();
        }
        const size_t b = p;
        bool flt = false;
        if (s[p] == '-') ++p;
        while (p < s.size() && ((s[p] >= '0' && s[p] <= '9') || s[p] == '.' || s[p] == 'e' || s[p] == 'E' ||
                                s[p] == '+' || s[p] == '-')) {
            if (s[p] == '.' || s[p] == 'e' || s[p] == 'E') flt = true;
            ++p;
        }
        if (p == b) fail("unexpected character");
        const std::string_view t = s.substr(b, p - b);
        if (flt) {
            double d = 0;
            std::from_chars(t.data(), t.data() + t.size(), d);
            return Json(d);
        }
        long long v = 0;
        std::from_chars(t.data(), t.data() + t.size(), v);
        return Json(v);
    }
};

void put_str(std::string& o, const std::string& s) {
    o += '"';
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c == '\b') o += "\\b";
        else if (c == '\f') o += "\\f";
        else if (c < 0x20 || c >= 0x7F) {
            // ensure_ascii: decode UTF-8 and escape (latin1 fallback for bad bytes)
            uint32_t cp = c;
            size_t n = 1;
            if (c >= 0xC0 && c < 0xE0 && i + 1 < s.size()) { cp = ((c & 0x1Fu) << 6) | (s[i + 1] & 0x3F); n = 2; }
            else if (c >= 0xE0 && c < 0xF0 && i + 2 < s.size()) {
                cp = ((c & 0x0Fu) << 12) | ((s[i + 1] & 0x3Fu) << 6) | (s[i + 2] & 0x3F);
                n = 3;
            } else if (c >= 0xF0 && i + 3 < s.size()) {
                cp = ((c & 0x07u) << 18) | ((s[i + 1] & 0x3Fu) << 12) | ((s[i + 2] & 0x3Fu) << 6) | (s[i + 3] & 0x3F);
                n = 4;
            }
            char buf[16];
            if (cp >= 0x10000) {
                const uint32_t v = cp - 0x10000;
                std::snprintf(buf, sizeof buf, "\\u%04x\\u%04x", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF));
            } else {
                std::snprintf(buf, sizeof buf, "\\u%04x", cp);
            }
            o += buf;
            i += n;
            continue;
        } else {
            o += static_cast<char>(c);
        }
        ++i;
    }
    o += '"';
}

}  // namespace

Json Json::parse(std::string_view text) {
    Parser ps{text};
    Json v = ps.value();
    return v;
}

void Json::dump_to(std::string& o, int indent, int level) const {
    switch (t_) {
        case NUL: o += "null"; return;
        case BOOL: o += i_ ? "true" : "false"; return;
        case INT: o += std::to_string(i_); return;
        case DBL: {
            char buf[64];
            auto r = std::to_chars(buf, buf + sizeof buf, d_);
            std::string t(buf, r.ptr);
            if (t.find_first_of(".eEn") == std::string::npos) t += ".0";
            o += t;
            return;
        }
        case STR: put_str(o, s_); return;
        case ARR:
        case OBJ: {
            const bool obj = t_ == OBJ;
            if (a_.empty()) {
                o += obj ? "{}" : "[]";
                return;
            }
            o += obj ? '{' : '[';
            for (size_t k = 0; k < a_.size(); ++k) {
                if (k) o += ',';
                o += '\n';
                o.append(static_cast<size_t>(indent * (level + 1)), ' ');
                if (obj) {
                    put_str(o, keys_[k]);
                    o += ": ";
                }
                a_[k].dump_to(o, indent, level + 1);
            }
            o += '\n';
            o.append(static_cast<size_t>(indent * level), ' ');
            o += obj ? '}' : ']';
            return;
        }
    }
}

std::string Json::dump(int indent) const {
    std::string o;
    dump_to(o, indent, 0);
    return o;
}

Json load_json(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string t = ss.str();
    return Json::parse(t);
}

}  // namespace flow
