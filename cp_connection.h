#include <optional>

#include <librlcom/connection.h>

#include "rsa.h"
#include "aes.h"
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

        void init_as_client(RSA const &rsa);
        void init_as_server(RSA const &rsa);

        void encrypt_and_flush();
        void gather_and_decrypt();

        void ensure_send_buffer_empty() const;
        void ensure_recv_buffer_empty() const;

    private:
        void verify_initialized();

        void reset_send_buffer();
        void set_send_buffer_size();
        void encrypt();
        void flush();

        void reset_recv_buffer();
        void set_recv_buffer_size();
        void gather();
        void decrypt();

        Connection &conn_;
        std::vector<std::byte> send_buffer_;
        std::vector<std::byte> recv_buffer_;
        size_t recv_offset_;

        std::optional<AES> aes_;
    };

}
