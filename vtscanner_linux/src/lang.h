#pragma once
#include <string>
#include <unordered_map>

enum class Lang { RU, EN };

std::string T(Lang lang, const std::string& key);

inline Lang LangFromString(const std::string& s) { return s == "en" ? Lang::EN : Lang::RU; }
inline std::string LangToString(Lang l) { return l == Lang::EN ? "en" : "ru"; }