// A small JSON value with insertion-ordered objects (like a Python dict),
// a reader, and a writer that formats like json.dump(..., indent=1).
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace flow {

class Json {
public:
    enum Type { NUL, BOOL, INT, DBL, STR, ARR, OBJ };

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool b) : t_(BOOL), i_(b) {}
    Json(int v) : t_(INT), i_(v) {}
    Json(unsigned v) : t_(INT), i_(v) {}
    Json(long v) : t_(INT), i_(v) {}
    Json(long long v) : t_(INT), i_(v) {}
    Json(unsigned long v) : t_(INT), i_(static_cast<int64_t>(v)) {}
    Json(unsigned long long v) : t_(INT), i_(static_cast<int64_t>(v)) {}
    Json(double v) : t_(DBL), d_(v) {}
    Json(const char* s) : t_(STR), s_(s) {}
    Json(std::string s) : t_(STR), s_(std::move(s)) {}
    Json(std::string_view s) : t_(STR), s_(s) {}

    static Json array() {
        Json j;
        j.t_ = ARR;
        return j;
    }
    static Json object() {
        Json j;
        j.t_ = OBJ;
        return j;
    }
    template <class It> static Json array(It b, It e) {
        Json j = array();
        for (; b != e; ++b) j.push(Json(*b));
        return j;
    }

    Type type() const { return t_; }
    bool is_null() const { return t_ == NUL; }
    bool is_obj() const { return t_ == OBJ; }
    bool is_arr() const { return t_ == ARR; }
    bool is_str() const { return t_ == STR; }
    bool is_num() const { return t_ == INT || t_ == DBL; }
    bool truthy() const;  // Python truth value

    int64_t as_int() const { return t_ == DBL ? static_cast<int64_t>(d_) : i_; }
    bool as_bool() const { return i_ != 0; }
    const std::string& as_str() const { return s_; }
    const std::vector<Json>& items() const { return a_; }
    std::vector<Json>& items() { return a_; }
    size_t size() const { return t_ == OBJ ? keys_.size() : a_.size(); }

    // object access
    const Json* get(std::string_view k) const;
    bool has(std::string_view k) const { return get(k) != nullptr; }
    Json& operator[](const std::string& k);  // inserts (keeps first position)
    void erase(std::string_view k);          // dict.pop(k, None)
    const std::vector<std::string>& keys() const { return keys_; }
    const Json& at(size_t i) const { return a_[i]; }  // object values by position, or array items

    void push(Json v) { a_.push_back(std::move(v)); }

    static Json parse(std::string_view text);
    std::string dump(int indent = 1) const;

private:
    void dump_to(std::string& o, int indent, int level) const;
    Type t_ = NUL;
    int64_t i_ = 0;
    double d_ = 0;
    std::string s_;
    std::vector<Json> a_;            // array items, or object values in order
    std::vector<std::string> keys_;  // object keys in order
    std::map<std::string, size_t, std::less<>> idx_;
};

Json load_json(const std::string& path);

}  // namespace flow
