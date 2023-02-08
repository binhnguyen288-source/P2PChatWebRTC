#pragma once
#include "sqlite3/sqlite3.h"
#include <stdexcept>
#include <vector>
#include <unordered_map>

struct SQLiteDriver {
private:
    static inline sqlite3* open_sqlite3(const char* name) {
        sqlite3* temp;
        int ret = sqlite3_open(name, &temp);
        if (ret != SQLITE_OK)
            throw std::runtime_error("open database failed");
        return temp;
    }
    static int query_callback(void* arg, int ncol, char** values, char** colnames) {
        auto list = static_cast<std::vector<std::unordered_map<std::string, std::string>>*>(arg);
        std::unordered_map<std::string, std::string> entry;
        for (int i = 0; i < ncol; ++i) {
            entry.insert({ colnames[i], values[i] });
        }
        list->push_back(std::move(entry));
        return SQLITE_OK;
    }
public:
    SQLiteDriver(const char* name) : db{open_sqlite3(name)} {}
    ~SQLiteDriver() { sqlite3_close(db); }
    void exec(std::string const& query, int (*callback)(void*, int, char**, char**) = nullptr, void* arg = nullptr, char** errmsg = nullptr) {
        int ret = sqlite3_exec(db, query.c_str(), callback, arg, errmsg);
        if (ret != SQLITE_OK) {
            throw std::runtime_error("sqlite3 exec error " + std::to_string(ret));
        }
    }
    std::vector<std::unordered_map<std::string, std::string>> query(std::string const& query) {
        std::vector<std::unordered_map<std::string, std::string>> list;
        exec(query, query_callback, &list);
        return list;
    }
private:
    sqlite3* db;
};