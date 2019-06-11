#include <librlcom/connection.h>

#include "bytes.h"

namespace rrl::rlc {

    // Crypto Proxy Connection
    class CPConnection : public rrl::Connection {
    public:
        CPConnection(rrl::Connection &conn);
        virtual ~CPConnection();

        virtual void connect(rrl::Address const &address) override;
        virtual void disconnect() override;
        virtual void send(std::byte const *data, uint64_t length) override;
        virtual void recv(std::byte *data, uint64_t length) override;

        void init_as_client(Bytes const& server_pk_modulus, Bytes const& server_pk_exponent);
        void init_as_server();

        void encrypt_and_flush();
        void gather_and_decrypt();

    private:
        void encrypt();
        void flush();

        void gather();
        void decrypt();

        Connection &conn_;
        std::vector<std::byte> send_buffer_;
        std::vector<std::byte> recv_buffer_;
        size_t recv_offset_;

        Bytes key_;
    };

}
