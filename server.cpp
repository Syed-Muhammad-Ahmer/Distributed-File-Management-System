#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <thread>
#include <map>
#include <sstream>
#include <ctime>
#include <filesystem>
#include <chrono>
#include <iomanip>
namespace fs = std::filesystem;
using boost::asio::ip::tcp;

struct FileMetadata
{
    std::string filename;
    size_t size;
    std::string owner;
    std::string upload_time;
    bool deleted;
    std::string deleted_time;
};

std::map<std::string, FileMetadata> file_index_map;
std::map<std::string, std::string> user_credentials;

const std::string STORAGE_BASE_DIR = "./storage/";
const std::string TRASH_DIR = STORAGE_BASE_DIR + "trash/";
const std::string INDEX_FILE = "file_index.dat";
const std::string USERS_FILE = "users.dat";

void save_to_index_file()
{
    std::ofstream out(INDEX_FILE);
    if (!out) {
        std::cerr << "Failed to open index file for writing" << std::endl;
        return;
    }
    for (const auto& [filename, meta] : file_index_map) {
        out << filename << "|" << meta.size << "|" << meta.owner << "|" << meta.upload_time << "|"
            << (meta.deleted ? "1" : "0") << "|" << meta.deleted_time << "\n";
    }
    if (!out) {
        std::cerr << "Error writing to index file" << std::endl;
    }
}

void load_index()
{
    std::ifstream in(INDEX_FILE);
    if (!in) return;
    std::string line;
    while (std::getline(in, line))
    {
        std::stringstream ss(line);
        std::string filename, size_str, owner, upload_time, deleted_str, deleted_time;
        std::getline(ss, filename, '|');
        std::getline(ss, size_str, '|');
        std::getline(ss, owner, '|');
        std::getline(ss, upload_time, '|');
        std::getline(ss, deleted_str, '|');
        std::getline(ss, deleted_time, '|');
        try {
            if (filename.empty() || size_str.empty() || owner.empty() || upload_time.empty()) {
                std::cerr << "Skipping malformed line: " << line << std::endl;
                continue;
            }
            size_t size = std::stoul(size_str);
            bool deleted = deleted_str == "1";
            file_index_map[filename] = { filename, size, owner, upload_time, deleted, deleted_time };
        }
        catch (const std::exception& e) {
            std::cerr << "Failed to parse line: " << line << " - Error: " << e.what() << std::endl;
        }
    }
}

void load_users()
{
    std::ifstream in(USERS_FILE);
    if (!in) return;
    std::string line;
    while (std::getline(in, line))
    {
        std::stringstream ss(line);
        std::string username, password;
        std::getline(ss, username, '|');
        std::getline(ss, password, '|');
        if (!username.empty() && !password.empty()) {
            user_credentials[username] = password;
        }
    }
}

void save_users()
{
    std::ofstream out(USERS_FILE);
    if (!out) {
        std::cerr << "Failed to open users file for writing" << std::endl;
        return;
    }
    for (const auto& [username, password] : user_credentials) {
        out << username << "|" << password << "\n";
    }
    if (!out) {
        std::cerr << "Error writing to users file" << std::endl;
    }
}

std::string get_current_time()
{
    std::time_t now = std::time(nullptr);
    char buf[26];
    ctime_s(buf, sizeof(buf), &now);
    std::string time_str(buf);
    time_str.erase(time_str.find_last_not_of("\r\n") + 1);
    return time_str;
}

std::chrono::system_clock::time_point parse_time(const std::string& time_str)
{
    std::tm tm = {};
    std::istringstream ss(time_str);
    ss >> std::get_time(&tm, "%a %b %d %H:%M:%S %Y");
    if (ss.fail()) {
        std::cerr << "Failed to parse time: " << time_str << std::endl;
        return std::chrono::system_clock::time_point();
    }
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

void purge_old_trash()
{
    const auto retention_period = std::chrono::hours(60*25); // 30 days
    auto now = std::chrono::system_clock::now();
    std::vector<std::string> to_remove;
    for (const auto& [filename, meta] : file_index_map) {
        if (meta.deleted && !meta.deleted_time.empty()) {
            auto deleted_time = parse_time(meta.deleted_time);
            if (deleted_time != std::chrono::system_clock::time_point()) {
                auto duration = now - deleted_time;
                if (duration >= retention_period) {
                    std::string trash_path = TRASH_DIR + filename;
                    try {
                        if (fs::exists(trash_path)) {
                            fs::remove(trash_path);
                            std::cout << "Purged old trash file: " << filename << std::endl;
                        }
                        to_remove.push_back(filename);
                    }
                    catch (const fs::filesystem_error& e) {
                        std::cerr << "Failed to remove trash file " << filename << ": " << e.what() << std::endl;
                    }
                }
            }
        }
    }
    for (const auto& filename : to_remove) {
        file_index_map.erase(filename);
    }
    if (!to_remove.empty()) {
        save_to_index_file();
    }
}

std::string generateUniqueFilename(const std::string& original, const std::string& username)
{
    std::string base = fs::path(original).stem().string();
    std::string ext = fs::path(original).extension().string();
    std::string candidate = username + "/" + base + ext;
    int counter = 1;
    while (file_index_map.count(candidate) > 0) {
        candidate = username + "/" + base + "_" + std::to_string(counter++) + ext;
    }
    return candidate;
}

void handle_client(tcp::socket socket)
{
    try {
        boost::asio::streambuf buf;
        std::istream is(&buf);
        std::string authenticated_user;
        while (true)
        {
            boost::system::error_code ec;
            boost::asio::read_until(socket, buf, "\n", ec);
            if (ec) {
                std::cerr << "Read error: " << ec.message() << std::endl;
                break;
            }
            std::string command;
            std::getline(is, command);
            std::stringstream ss(command);
            std::string op;
            ss >> op;

            if (op == "AUTH") {
                std::string username, password;
                ss >> username >> password;
                if (username.empty() || password.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("AUTH_FAILED Invalid credentials\n"));
                    continue;
                }
                if (user_credentials.find(username) == user_credentials.end()) {
                    user_credentials[username] = password;
                    save_users();
                    fs::create_directories(STORAGE_BASE_DIR + username);
                    authenticated_user = username;
                    boost::asio::write(socket, boost::asio::buffer("AUTH_SUCCESS Welcome, new user " + username + "!\n"));
                }
                else if (user_credentials[username] == password) {
                    authenticated_user = username;
                    boost::asio::write(socket, boost::asio::buffer("AUTH_SUCCESS\n"));
                }
                else {
                    boost::asio::write(socket, boost::asio::buffer("AUTH_FAILED Incorrect password\n"));
                }
            }
            else if (op == "UPLOAD") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::string filename, owner;
                size_t file_size;
                ss >> filename >> owner >> file_size;
                if (owner != authenticated_user) {
                    boost::asio::write(socket, boost::asio::buffer("PERMISSION_DENIED\n"));
                    continue;
                }
                std::string server_filename = generateUniqueFilename(filename, authenticated_user);
                std::string full_path = STORAGE_BASE_DIR + server_filename;
                std::ofstream out(full_path, std::ios::binary);
                if (!out) {
                    boost::asio::write(socket, boost::asio::buffer("UPLOAD_FAILED\n"));
                    continue;
                }
                size_t received = 0;
                std::vector<char> buffer(1024);
                while (received < file_size) {
                    size_t to_read = std::min(buffer.size(), file_size - received);
                    size_t bytes = boost::asio::read(socket, boost::asio::buffer(buffer.data(), to_read));
                    out.write(buffer.data(), bytes);
                    received += bytes;
                }
                out.close();
                file_index_map[server_filename] = { server_filename, file_size, owner, get_current_time(), false, "" };
                save_to_index_file();
                boost::asio::write(socket, boost::asio::buffer("UPLOAD_SUCCESS " + server_filename + "\n"));
            }
            else if (op == "DOWNLOAD") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::string filename;
                ss >> filename;
                if (!file_index_map.count(filename) || file_index_map[filename].owner != authenticated_user || file_index_map[filename].deleted) {
                    boost::asio::write(socket, boost::asio::buffer("FILE_NOT_FOUND\n"));
                    continue;
                }
                std::ifstream in(STORAGE_BASE_DIR + filename, std::ios::binary);
                if (!in) {
                    boost::asio::write(socket, boost::asio::buffer("FILE_NOT_FOUND\n"));
                    continue;
                }
                in.seekg(0, std::ios::end);
                size_t file_size = in.tellg();
                in.seekg(0, std::ios::beg);
                std::string header = "FILE_SIZE " + std::to_string(file_size) + "\n";
                boost::asio::write(socket, boost::asio::buffer(header));
                std::vector<char> buffer(1024);
                while (in) {
                    in.read(buffer.data(), buffer.size());
                    boost::asio::write(socket, boost::asio::buffer(buffer.data(), in.gcount()));
                }
                in.close();
            }
            else if (op == "LIST") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::ostringstream response;
                for (const auto& [filename, meta] : file_index_map) {
                    if (meta.owner == authenticated_user && !meta.deleted) {
                        response << filename << " | " << meta.size << " bytes | " << meta.owner << " | " << meta.upload_time << "\n";
                    }
                }
                response << "LIST_END\n";
                boost::asio::write(socket, boost::asio::buffer(response.str()));
            }
            else if (op == "LIST_DELETED") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::ostringstream response;
                for (const auto& [filename, meta] : file_index_map) {
                    if (meta.owner == authenticated_user && meta.deleted) {
                        response << filename << " | " << meta.size << " bytes | " << meta.owner << " | " << meta.deleted_time << "\n";
                    }
                }
                response << "LIST_DELETED_END\n";
                boost::asio::write(socket, boost::asio::buffer(response.str()));
            }
            else if (op == "DELETE") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::string filename;
                ss >> filename;
                if (!file_index_map.count(filename) || file_index_map[filename].owner != authenticated_user || file_index_map[filename].deleted) {
                    boost::asio::write(socket, boost::asio::buffer("FILE_NOT_FOUND\n"));
                    continue;
                }
                std::string trash_path = TRASH_DIR + filename;
                fs::create_directories(fs::path(trash_path).parent_path());
                fs::rename(STORAGE_BASE_DIR + filename, trash_path);
                file_index_map[filename].deleted = true;
                file_index_map[filename].deleted_time = get_current_time();
                save_to_index_file();
                boost::asio::write(socket, boost::asio::buffer("DELETE_SUCCESS\n"));
            }
            else if (op == "SYNC") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::ostringstream response;
                for (const auto& [filename, meta] : file_index_map) {
                    if (meta.owner == authenticated_user) {
                        response << filename << "|" << meta.size << "|" << meta.upload_time << "|"
                            << (meta.deleted ? "1" : "0") << "|" << meta.deleted_time << "\n";
                    }
                }
                response << "SYNC_END\n";
                boost::asio::write(socket, boost::asio::buffer(response.str()));
            }
            else if (op == "RESTORE") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::string filename;
                ss >> filename;
                if (!file_index_map.count(filename) || file_index_map[filename].owner != authenticated_user || !file_index_map[filename].deleted) {
                    boost::asio::write(socket, boost::asio::buffer("FILE_NOT_FOUND\n"));
                    continue;
                }
                std::string trash_path = TRASH_DIR + filename;
                std::string original_path = STORAGE_BASE_DIR + filename;
                fs::create_directories(fs::path(original_path).parent_path());
                fs::rename(trash_path, original_path);
                file_index_map[filename].deleted = false;
                file_index_map[filename].deleted_time = "";
                save_to_index_file();
                boost::asio::write(socket, boost::asio::buffer("RESTORE_SUCCESS\n"));
            }
            else if (op == "PURGE_TRASH") {
                if (authenticated_user.empty()) {
                    boost::asio::write(socket, boost::asio::buffer("NOT_AUTHENTICATED\n"));
                    continue;
                }
                std::vector<std::string> to_remove;
                for (const auto& [filename, meta] : file_index_map) {
                    if (meta.owner == authenticated_user && meta.deleted) {
                        std::string trash_path = TRASH_DIR + filename;
                        try {
                            if (fs::exists(trash_path)) {
                                fs::remove(trash_path);
                                std::cout << "Purged trash file: " << filename << std::endl;
                            }
                            to_remove.push_back(filename);
                        }
                        catch (const fs::filesystem_error& e) {
                            std::cerr << "Failed to remove trash file " << filename << ": " << e.what() << std::endl;
                        }
                    }
                }
                for (const auto& filename : to_remove) {
                    file_index_map.erase(filename);
                }
                if (!to_remove.empty()) {
                    save_to_index_file();
                }
                boost::asio::write(socket, boost::asio::buffer("PURGE_TRASH_SUCCESS\n"));
            }
            else {
                boost::asio::write(socket, boost::asio::buffer("INVALID_COMMAND\n"));
            }
        }
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
    }
    socket.close();
}

int main()
{
    try {
        if (!fs::exists(STORAGE_BASE_DIR)) fs::create_directory(STORAGE_BASE_DIR);
        if (!fs::exists(TRASH_DIR)) fs::create_directory(TRASH_DIR);
        load_index();
        load_users();

        std::thread trash_cleanup_thread([]() {
            while (true) {
                try {
                    purge_old_trash();
                }
                catch (const std::exception& e) {
                    std::cerr << "Trash cleanup error: " << e.what() << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::hours(1));
            }
            });
        trash_cleanup_thread.detach();

        boost::asio::io_context io;
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 8080));
        std::cout << "Server is running on port 8080...\n";
        while (true) {
            tcp::socket socket(io);
            acceptor.accept(socket);
            std::thread(handle_client, std::move(socket)).detach();
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
