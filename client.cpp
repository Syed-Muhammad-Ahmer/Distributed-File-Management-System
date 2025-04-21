#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
namespace fs = std::filesystem;
using boost::asio::ip::tcp;
std::vector<std::string>filenames;

void upload_file(tcp::socket& socket, const std::string& filename, const std::string& owner) {
    std::ifstream infile(filename, std::ios::binary);
    if (!infile) {
        std::cout << "File not found: " << filename << "\n";
        return;
    }

    infile.seekg(0, std::ios::end);
    size_t file_size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    // Send UPLOAD command with metadata 
    std::ostringstream header;
    header << "UPLOAD " << filename << " " << owner << " " << file_size << "\n";
    boost::asio::write(socket, boost::asio::buffer(header.str()));

    // Send file content in chunks
    std::vector<char> buffer(1024);
    while (infile) {
        infile.read(buffer.data(), buffer.size());
        std::streamsize bytes_read = infile.gcount();
        if (bytes_read > 0) {
            boost::asio::write(socket, boost::asio::buffer(buffer.data(), bytes_read));
        }
    }
    infile.close();

    // Wait for server response
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    std::cout << "Server response: " << line << "\n";
}

void download_file(tcp::socket& socket, const std::string& filename) 
{
    std::string command = "DOWNLOAD " + filename + "\n";
    boost::asio::write(socket, boost::asio::buffer(command));

    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string header;
    std::getline(resp_stream, header);

    if (header.find("FILE_NOT_FOUND") != std::string::npos) {
        std::cout << "File not found on server.\n";
        return;
    }

    if (header.find("FILE_SIZE ") != 0) {
        std::cout << "Unexpected server response: " << header << "\n";
        return;
    }

    size_t file_size;
    try {
        file_size = std::stoul(header.substr(10));
    }
    catch (const std::exception& e) {
        std::cout << "Invalid file size: " << header << "\n";
        return;
    }

    std::ofstream outfile("./storage/"+filename, std::ios::binary);
    if (!outfile) {
        std::cout << "Failed to create local file: " << filename << "\n";
        return;
    }
    //store the downloaded content.
    size_t total_received = 0;
    std::vector<char> buffer(1024);
    while (total_received < file_size) {
        size_t to_read = std::min(buffer.size(), file_size - total_received);//is lat chunk
        size_t bytes = boost::asio::read(socket, boost::asio::buffer(buffer.data(), to_read));
        outfile.write(buffer.data(), bytes);
        total_received += bytes;
    }
    outfile.close();
    std::cout << "File downloaded successfully (" << total_received << " bytes).\n";
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

void delete_file(tcp::socket& socket, const std::string& filename) {
    std::string command = "DELETE " + filename + "\n";
    boost::asio::write(socket, boost::asio::buffer(command));

    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\n");
    std::istream resp_stream(&response);
    std::string line;
    std::getline(resp_stream, line);
    std::cout << "Server response: " << line << "\n";
}

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);//combine address and port no.
        auto endpoints = resolver.resolve("127.0.0.1", "8080");
        tcp::socket socket(io_context);
        boost::asio::connect(socket, endpoints);

        std::string command;
        while (true) {
            std::cout << "\nEnter command (UPLOAD <file> <owner>, DOWNLOAD <file>, LIST, DELETE <file>, EXIT): ";
            std::getline(std::cin, command);

            std::stringstream ss(command);
            std::string operation;
            ss >> operation;

            if (operation == "UPLOAD") {
                std::string filename, owner;
                if (!(ss >> filename >> owner)) {
                    std::cout << "Usage: UPLOAD <filename> <owner>\n";
                    continue;
                }
                upload_file(socket, filename, owner);
            }
            else if (operation == "DOWNLOAD") {
                std::string filename;
                if (!(ss >> filename)) {
                    std::cout << "Usage: DOWNLOAD <filename>\n";
                    continue;
                }
                download_file(socket, filename);
            }
            else if (operation == "LIST") {
                list_files(socket);
            }
            else if (operation == "DELETE") {
                std::string filename;
                if (!(ss >> filename)) {
                    std::cout << "Usage: DELETE <filename>\n";
                    continue;
                }
                delete_file(socket, filename);
            }
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
