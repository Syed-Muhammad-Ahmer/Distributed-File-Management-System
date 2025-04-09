#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>

namespace fs = std::filesystem;
using boost::asio::ip::tcp;

class FileStorageServer {
public:
    FileStorageServer(boost::asio::io_context& io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        loadFileIndex();
        startAccept();
    }

private:
    struct FileMetadata {
        std::string filename;
        size_t size;
        std::string owner;
        std::time_t upload_time;
    };

    std::unordered_map<std::string, FileMetadata> file_index_;
    std::mutex file_mutex_;
    tcp::acceptor acceptor_;

    void loadFileIndex() {
        std::lock_guard<std::mutex> lock(file_mutex_);
        std::ifstream index_file("file_index.dat");
        if (!index_file) return; // No file exists, skip loading

        file_index_.clear();
        std::string line;

        while (std::getline(index_file, line)) {
            std::istringstream iss(line);
            FileMetadata meta;
            std::string size_str, upload_time_str;

            if (std::getline(iss, meta.filename, '|') &&
                std::getline(iss, size_str, '|') &&
                std::getline(iss, meta.owner, '|') &&
                std::getline(iss, upload_time_str)) {

                meta.size = std::stoull(size_str);
                meta.upload_time = std::stoll(upload_time_str);
                file_index_[meta.filename] = meta;
            }
        }
    }

    void saveFileIndex() {
        std::lock_guard<std::mutex> lock(file_mutex_);
        std::ofstream index_file("file_index.dat");
        if (!index_file) return;

        for (const auto& [filename, meta] : file_index_) {
            index_file << meta.filename << "|"
                << meta.size << "|"
                << meta.owner << "|"
                << meta.upload_time << "\n";
        }
    }

    void startAccept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::thread(&FileStorageServer::handleClient, this, std::move(socket)).detach();
                }
                startAccept();
            });
    }

    void handleClient(tcp::socket socket) {
        try {
            boost::asio::streambuf buf;
            boost::asio::read_until(socket, buf, '\n');
            std::istream is(&buf);
            std::string command;
            std::getline(is, command);

            if (command == "UPLOAD") {
                handleUpload(socket);
            }
            else if (command == "DOWNLOAD") {
                handleDownload(socket);
            }
            else if (command == "LIST") {
                handleList(socket);
            }
            else if (command == "DELETE") {
                handleDelete(socket);
            }
        }
        catch (std::exception& e) {
            std::cerr << "Client handling exception: " << e.what() << std::endl;
        }
    }

    void handleUpload(tcp::socket& socket) {
        // Read metadata
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, '\n');
        std::istream is(&buf);

        FileMetadata meta;
        std::getline(is, meta.filename);
        std::getline(is, meta.owner);
        is >> meta.size;

        // Create unique filename
        std::string server_filename = generateUniqueFilename(meta.filename);
        meta.upload_time = std::time(nullptr);

        // Save file
        std::ofstream file("storage/" + server_filename, std::ios::binary);
        size_t remaining = meta.size;

        while (remaining > 0) {
            char data[1024];
            size_t to_read = std::min(sizeof(data), remaining);
            size_t bytes_read = socket.read_some(boost::asio::buffer(data, to_read));
            file.write(data, bytes_read);
            remaining -= bytes_read;
        }

        // Update index
        {
            std::lock_guard<std::mutex> lock(file_mutex_);
            file_index_[server_filename] = meta;
        }

        saveFileIndex();
        boost::asio::write(socket, boost::asio::buffer("UPLOAD_SUCCESS\n"));
    }

    void handleDownload(tcp::socket& socket) {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, '\n');
        std::istream is(&buf);
        std::string filename;
        std::getline(is, filename);

        std::lock_guard<std::mutex> lock(file_mutex_);
        auto it = file_index_.find(filename);
        if (it == file_index_.end()) {
            boost::asio::write(socket, boost::asio::buffer("FILE_NOT_FOUND\n"));
            return;
        }

        // Send metadata
        boost::asio::write(socket, boost::asio::buffer(it->second.filename + "\n"));
        boost::asio::write(socket, boost::asio::buffer(std::to_string(it->second.size) + "\n"));

        // Send file data
        std::ifstream file("storage/" + filename, std::ios::binary);
        char data[1024];
        while (file) {
            file.read(data, sizeof(data));
            boost::asio::write(socket, boost::asio::buffer(data, file.gcount()));
        }
    }

    void handleList(tcp::socket& socket) {
        std::lock_guard<std::mutex> lock(file_mutex_);
        for (const auto& entry : file_index_) {
            std::string info = entry.second.filename + "|" +
                std::to_string(entry.second.size) + "|" +
                entry.second.owner + "|" +
                std::to_string(entry.second.upload_time) + "\n";
            boost::asio::write(socket, boost::asio::buffer(info));
        }
        boost::asio::write(socket, boost::asio::buffer("LIST_END\n"));
    }

    void handleDelete(tcp::socket& socket) {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, '\n');
        std::istream is(&buf);
        std::string filename;
        std::getline(is, filename);

        {
            std::lock_guard<std::mutex> lock(file_mutex_);
            if (file_index_.erase(filename) == 0) {
                boost::asio::write(socket, boost::asio::buffer("FILE_NOT_FOUND\n"));
                return;
            }
        }

        fs::remove("storage/" + filename);
        saveFileIndex();
        boost::asio::write(socket, boost::asio::buffer("DELETE_SUCCESS\n"));
    }

    std::string generateUniqueFilename(const std::string& original) {
        std::string base = fs::path(original).stem().string();
        std::string ext = fs::path(original).extension().string();
        std::string candidate = base + ext;

        int counter = 1;
        while (file_index_.count(candidate) > 0) {
            candidate = base + "_" + std::to_string(counter++) + ext;
        }

        return candidate;
    }
};

int main() {
    try {
        // Create storage directory if it doesn't exist
        if (!fs::exists("storage")) {
            fs::create_directory("storage");
        }

        boost::asio::io_context io_context;
        FileStorageServer server(io_context, 1234);
        std::cout << "File Storage Server running on port 1234" << std::endl;
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}
