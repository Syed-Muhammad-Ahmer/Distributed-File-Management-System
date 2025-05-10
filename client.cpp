
#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
namespace fs = std::filesystem;
using boost::asio::ip::tcp;

struct FileMetadata
{
    std::string filename;
    size_t size;
    std::string upload_time;
    bool deleted;
    std::string deleted_time;
};

std::map<std::string, FileMetadata> local_index_map;
const std::string LOCAL_STORAGE_BASE = "./storage/";
std::vector<std::pair<std::string, std::string>> offline_queue;
std::string get_current_time() {
    std::time_t now = std::time(nullptr);
    char buf[26];
    ctime_s(buf, sizeof(buf), &now);
    std::string time_str(buf);
    time_str.erase(time_str.find_last_not_of("\r\n") + 1);
    return time_str;
}
void scan_local_directory(const std::string& username) {
    std::string user_dir = LOCAL_STORAGE_BASE + username;
    if (!fs::exists(user_dir)) return;
    std::map<std::string, FileMetadata> new_index;
    for (const auto& entry : fs::directory_iterator(user_dir)) {
        if (entry.is_regular_file()) {
            std::string filename = username + "/" + entry.path().filename().string();
            size_t size = fs::file_size(entry);
            std::string mod_time = get_current_time();
            new_index[filename] = { filename, size, mod_time, false, "" };
        }
    }
    for (const auto& [filename, meta] : local_index_map) {
        if (!meta.deleted && new_index.find(filename) == new_index.end()) {
            new_index[filename] = meta;
            new_index[filename].deleted = true;
            new_index[filename].deleted_time = get_current_time();
        }
    }
    local_index_map = new_index;
}
bool authenticate(tcp::socket& socket, const std::string& username, const std::string& password) {
    std::string command = "AUTH " + username + " " + password + "\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    if (line.find("AUTH_SUCCESS") == 0) {
        std::cout << line.substr(12) << "\n";
        return true;
    }
    else {
        std::cout << line.substr(11) << "\n";
        return false;
    }
}

void upload_file(tcp::socket& socket, const std::string& filename, const std::string& owner) {
    std::string local_path = LOCAL_STORAGE_BASE + owner + "/" + filename;
    std::ifstream infile(local_path, std::ios::binary);
    if (!infile) {
        std::cout << "File not found: " << local_path << "\n";
        return;
    }
    infile.seekg(0, std::ios::end);
    size_t file_size = infile.tellg();
    infile.seekg(0, std::ios::beg);
    std::vector<unsigned char> plaintext(file_size);
    infile.read(reinterpret_cast<char*>(plaintext.data()), file_size);
    infile.close();

    unsigned char key[32];
    RAND_bytes(key, sizeof(key));
    unsigned char iv[12];
    RAND_bytes(iv, sizeof(iv));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(file_size + 16);
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> full_encrypted(iv, iv + 12);
    full_encrypted.insert(full_encrypted.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    full_encrypted.insert(full_encrypted.end(), tag, tag + 16);

    std::ostringstream header;
    header << "UPLOAD " << filename << " " << owner << " " << full_encrypted.size() << "\n";
    boost::asio::write(socket, boost::asio::buffer(header.str()));
    boost::asio::write(socket, boost::asio::buffer(full_encrypted));

    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    std::stringstream ss(line);
    std::string status, server_filename;
    ss >> status;
    if (status == "UPLOAD_SUCCESS") {
        ss >> server_filename;
        std::cout << "Upload successful, server filename: " << server_filename << "\n";
        std::string key_dir = LOCAL_STORAGE_BASE + "keys/" + owner;
        fs::create_directories(key_dir);
        std::string key_filename = key_dir + "/" + fs::path(server_filename).filename().string() + ".key";
        std::ofstream key_file(key_filename, std::ios::binary);
        if (key_file) {
            key_file.write(reinterpret_cast<char*>(key), sizeof(key));
            key_file.close();
        }
        local_index_map[server_filename] = { server_filename, file_size, get_current_time(), false, "" };
    }
    else {
        std::cout << "Server response: " << line << "\n";
    }
}

void download_file(tcp::socket& socket, const std::string& filename, const std::string& username) {
    std::string server_filename = username + "/" + filename;
    std::string command = "DOWNLOAD " + server_filename + "\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string header;
    std::getline(resp_stream, header);
    if (header.find("NOT_AUTHENTICATED") != std::string::npos || header.find("FILE_NOT_FOUND") != std::string::npos) {
        std::cout << "Server response: " << header << "\n";
        return;
    }
    if (header.find("FILE_SIZE ") != 0) {
        std::cout << "Unexpected response: " << header << "\n";
        return;
    }
    size_t file_size = std::stoul(header.substr(10));
    std::vector<unsigned char> encrypted_data(file_size);
    size_t total_received = 0;
    while (total_received < file_size) {
        size_t bytes = boost::asio::read(socket, boost::asio::buffer(encrypted_data.data() + total_received, file_size - total_received));
        total_received += bytes;
    }
    std::string key_path = LOCAL_STORAGE_BASE + "keys/" + server_filename + ".key";
    std::ifstream key_file(key_path, std::ios::binary);
    if (!key_file) {
        std::cout << "Key file not found: " << key_path << "\n";
        return;
    }
    unsigned char key[32];
    key_file.read(reinterpret_cast<char*>(key), sizeof(key));
    key_file.close();

    unsigned char iv[12];
    std::copy(encrypted_data.begin(), encrypted_data.begin() + 12, iv);
    unsigned char tag[16];
    std::copy(encrypted_data.end() - 16, encrypted_data.end(), tag);
    std::vector<unsigned char> ciphertext(encrypted_data.begin() + 12, encrypted_data.end() - 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> decrypted(ciphertext.size());
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) <= 0) {
        std::cout << "Decryption failed!\n";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    std::string output_path = LOCAL_STORAGE_BASE + username + "/" + filename;
    fs::create_directories(fs::path(output_path).parent_path());
    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile) {
        std::cout << "Failed to create output file: " << output_path << "\n";
        return;
    }
    outfile.write(reinterpret_cast<char*>(decrypted.data()), plaintext_len);
    outfile.close();
    std::cout << "File downloaded and decrypted successfully (" << plaintext_len << " bytes).\n";
}

void list_files(tcp::socket& socket) {
    std::string command = "LIST\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    while (true) {
        boost::asio::read_until(socket, response, "\n");
        std::istream resp_stream(&response);
        std::string line;
        std::getline(resp_stream, line);
        if (line == "LIST_END") break;
        std::cout << line << "\n";
    }
}

void list_deleted_files(tcp::socket& socket) {
    std::string command = "LIST_DELETED\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    while (true) {
        boost::asio::read_until(socket, response, "\n");
        std::istream resp_stream(&response);
        std::string line;
        std::getline(resp_stream, line);
        if (line == "LIST_DELETED_END") break;
        if (line.find("NOT_AUTHENTICATED") != std::string::npos) {
            std::cout << "Server response: Not authenticated.\n";
            return;
        }
        std::cout << line << "\n";
    }
}

void list_local_files(const std::string& username) {
    scan_local_directory(username);
    for (const auto& [filename, meta] : local_index_map) {
        if (!meta.deleted) {
            std::cout << filename << " | " << meta.size << " bytes | " << meta.upload_time << "\n";
        }
    }
}

void list_local_deleted_files(const std::string& username) {
    scan_local_directory(username);
    for (const auto& [filename, meta] : local_index_map) {
        if (meta.deleted) {
            std::cout << filename << " | " << meta.size << " bytes | " << meta.deleted_time << "\n";
        }
    }
}

void delete_file(tcp::socket& socket, const std::string& filename, const std::string& username) {
    std::string server_filename = username + "/" + filename;
    std::string command = "DELETE " + server_filename + "\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    std::cout << "Server response: " << line << "\n";
    if (line == "DELETE_SUCCESS") {
        local_index_map[server_filename].deleted = true;
        local_index_map[server_filename].deleted_time = get_current_time();
    }
}

void restore_file(tcp::socket& socket, const std::string& filename, const std::string& username) {
    std::string server_filename = username + "/" + filename;
    std::string command = "RESTORE " + server_filename + "\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    std::cout << "Server response: " << line << "\n";
    if (line == "RESTORE_SUCCESS") {
        local_index_map[server_filename].deleted = false;
        local_index_map[server_filename].deleted_time = "";
        download_file(socket, filename, username);
    }
}

void purge_trash(tcp::socket& socket) {
    std::string command = "PURGE_TRASH\n";
    boost::asio::write(socket, boost::asio::buffer(command));
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    if (line == "PURGE_TRASH_SUCCESS") {
        std::cout << "Trash purged successfully.\n";
    }
    else if (line.find("NOT_AUTHENTICATED") != std::string::npos) {
        std::cout << "Server response: Not authenticated.\n";
    }
    else {
        std::cout << "Server response: " << line << "\n";
    }
}




//void sync_files(tcp::socket& socket, const std::string& username) {
//    scan_local_directory(username);
//    std::string command = "SYNC\n";
//    boost::asio::write(socket, boost::asio::buffer(command));
//    boost::asio::streambuf response;
//    std::map<std::string, FileMetadata> server_index;
//    while (true) {
//        boost::asio::read_until(socket, response, "\n");
//        std::istream resp_stream(&response);
//        std::string line;
//        std::getline(resp_stream, line);
//        if (line == "SYNC_END") break;
//        std::stringstream ss(line);
//        std::string filename, size_str, upload_time, deleted_str, deleted_time;
//        std::getline(ss, filename, '|');
//        std::getline(ss, size_str, '|');
//        std::getline(ss, upload_time, '|');
//        std::getline(ss, deleted_str, '|');
//        std::getline(ss, deleted_time, '|');
//        size_t size = std::stoul(size_str);
//        bool deleted = deleted_str == "1";
//        server_index[filename] = { filename, size, upload_time, deleted, deleted_time };
//    }
//    for (const auto& [filename, server_meta] : server_index) {
//        auto local_it = local_index_map.find(filename);
//        if (local_it == local_index_map.end()) {
//            if (!server_meta.deleted) {
//                std::string local_filename = fs::path(filename).filename().string();
//                download_file(socket, local_filename, username);
//                local_index_map[filename] = server_meta;
//            }
//        }
//        else {
//            auto& local_meta = local_it->second;
//            if (!server_meta.deleted && !local_meta.deleted && server_meta.upload_time > local_meta.upload_time) {
//                std::string local_filename = fs::path(filename).filename().string();
//                download_file(socket, local_filename, username);
//                local_index_map[filename] = server_meta;
//            }
//            else if (server_meta.deleted && !local_meta.deleted) {
//                fs::remove(LOCAL_STORAGE_BASE + filename);
//                local_index_map[filename].deleted = true;
//                local_index_map[filename].deleted_time = server_meta.deleted_time;
//            }
//        }
//    }
//    for (const auto& [filename, local_meta] : local_index_map) {
//        auto server_it = server_index.find(filename);
//        if (server_it == server_index.end()) {
//            if (!local_meta.deleted) {
//                std::string local_filename = fs::path(filename).filename().string();
//                upload_file(socket, local_filename, username);
//            }
//        }
//        else {
//            auto& server_meta = server_it->second;
//            if (!local_meta.deleted && server_meta.deleted) {
//                std::string local_filename = fs::path(filename).filename().string();
//                upload_file(socket, local_filename, username);
//            }
//            else if (local_meta.deleted && !server_meta.deleted) {
//                delete_file(socket, fs::path(filename).filename().string(), username);
//            }
//        }
//    }
//    for (const auto& [op, filename] : offline_queue) {
//        if (op == "UPLOAD") {
//            upload_file(socket, filename, username);
//        }
//        else if (op == "DELETE") {
//            delete_file(socket, filename, username);
//        }
//    }
//    offline_queue.clear();
//}

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("127.0.0.1", "8080");
        tcp::socket socket(io_context);

        if (!fs::exists(LOCAL_STORAGE_BASE)) fs::create_directory(LOCAL_STORAGE_BASE);
        if (!fs::exists(LOCAL_STORAGE_BASE + "keys")) fs::create_directories(LOCAL_STORAGE_BASE + "keys");
        if (!fs::exists(LOCAL_STORAGE_BASE + "received")) fs::create_directories(LOCAL_STORAGE_BASE + "received");

        std::string username, password;
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        if (username.empty()) {
            std::cout << "Username cannot be empty.\n";
            return 1;
        }
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
        if (password.empty()) {
            std::cout << "Password cannot be empty.\n";
            return 1;
        }
        fs::create_directories(LOCAL_STORAGE_BASE + username);

        bool connected = false;
        try {
            boost::asio::connect(socket, endpoints);
            if (authenticate(socket, username, password)) {
                connected = true;
            }
            else {
                return 1;
            }
        }
        catch (const std::exception& e) {
            std::cout << "Connection failed: " << e.what() << "\n";
        }

      /*  std::thread sync_thread;
        if (connected) {
            sync_thread = std::thread([&socket, &username]() {
                while (true) {
                    try {
                        sync_files(socket, username);
                    }
                    catch (const std::exception& e) {
                        std::cout << "Sync error: " << e.what() << "\n";
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                }
                });
            sync_thread.detach();
        }*/

        std::string command;
        while (true) {
            std::cout << "\nEnter command (UPLOAD <file>, DOWNLOAD <file>, LIST, LIST_DELETED,  DELETE <file>, RESTORE <file>, PURGE_TRASH,  EXIT): ";
            std::getline(std::cin, command);
            std::stringstream ss(command);
            std::string operation;
            ss >> operation;

            if (operation == "UPLOAD") {
                std::string filename;
                if (!(ss >> filename)) {
                    std::cout << "Usage: UPLOAD <filename>\n";
                    continue;
                }
                if (!connected) {
                    offline_queue.emplace_back("UPLOAD", filename);
                    std::cout << "Offline: Queued UPLOAD " << filename << "\n";
                }
                else {
                    upload_file(socket, filename, username);
                }
            }
            else if (operation == "DOWNLOAD") {
                std::string filename;
                if (!(ss >> filename)) {
                    std::cout << "Usage: DOWNLOAD <filename>\n";
                    continue;
                }
                if (connected) {
                    download_file(socket, filename, username);
                }
                else {
                    std::cout << "Offline: Cannot download while disconnected.\n";
                }
            }
            else if (operation == "LIST") {
                if (connected) {
                    list_files(socket);
                }
                else {
                    std::cout << "Offline: Cannot list files. Use LIST_LOCAL to see local files.\n";
                }
            }
            else if (operation == "LIST_LOCAL") {
                list_local_files(username);
            }
            else if (operation == "LIST_DELETED") {
                if (connected) {
                    list_deleted_files(socket);
                }
                else {
                    std::cout << "Offline: Cannot list deleted files. Use LIST_DELETED_LOCAL to see local deleted files.\n";
                }
            }
            else if (operation == "LIST_DELETED_LOCAL") {
                list_local_deleted_files(username);
            }
            else if (operation == "DELETE") {
                std::string filename;
                if (!(ss >> filename)) {
                    std::cout << "Usage: DELETE <filename>\n";
                    continue;
                }
                if (!connected) {
                    offline_queue.emplace_back("DELETE", filename);
                    std::cout << "Offline: Queued DELETE " << filename << "\n";
                }
                else {
                    delete_file(socket, filename, username);
                }
            }
            else if (operation == "RESTORE") {
                std::string filename;
                if (!(ss >> filename)) {
                    std::cout << "Usage: RESTORE <filename>\n";
                    continue;
                }
                if (connected) {
                    restore_file(socket, filename, username);
                }
                else {
                    std::cout << "Offline: Cannot restore while disconnected.\n";
                }
            }
            else if (operation == "PURGE_TRASH") {
                if (connected) {
                    purge_trash(socket);
                }
                else {
                    std::cout << "Offline: Cannot purge trash while disconnected.\n";
                }
            }
            //else if (operation == "SYNC") {
            //    if (connected) {
            //        try {
            //            sync_files(socket, username);
            //            std::cout << "Sync completed successfully.\n";
            //        }
            //        catch (const std::exception& e) {
            //            //std BruSystem : ash failed : " << e.what() << "\n";
            //        }
            //    }
            //    else {
            //        std::cout << "Offline: Cannot sync while disconnected. Changes are queued.\n";
            //    }
            //}
            else if (operation == "EXIT") {
                break;
            }
            else {
                std::cout << "Invalid command.\n";
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
