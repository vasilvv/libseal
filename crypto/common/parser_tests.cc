#include "gtest/gtest.h"

#include "crypto/parser.hh"

struct data {
    uint8_t num1;
    uint16_t num2;
    uint32_t num3;  // Really 24-bit
    uint32_t num4;
    uint64_t num5;
};
typedef std::unique_ptr<data> data_u;

template <crypto::Endianness endianness>
class TestParser : public crypto::BaseParser<data, endianness> {
  protected:
    virtual data_u parse_core() override {
        data_u out(new data());
        out->num1 = this->read_uint8();
        out->num2 = this->read_uint16();
        out->num3 = this->read_uint24();
        out->num4 = this->read_uint32();
        out->num5 = this->read_uint64();
        return out;
    }
  public:
    TestParser(const crypto::memslice input) : crypto::BaseParser<data, endianness>(input) {}
    virtual ~TestParser() {};
};

TEST(BaseParser, TestDataLE) {
    crypto::bytestring input{0x10,
                             0x21, 0xa3,
                             0x44, 0x77, 0xdd,
                             0xab, 0xcd, 0xef, 0x43,
                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    TestParser<crypto::LittleEndian> parser(input.cmem());
    data_u output = parser.parse();
    ASSERT_NE(nullptr, output);
    EXPECT_EQ(0x10, output->num1);
    EXPECT_EQ(0xa321, output->num2);
    EXPECT_EQ(0xdd7744, output->num3);
    EXPECT_EQ(0x43efcdab, output->num4);
    EXPECT_EQ(0x8877665544332211, output->num5);
}

TEST(BaseParser, TestDataBE) {
    crypto::bytestring input{0x10,
                             0x21, 0xa3,
                             0x44, 0x77, 0xdd,
                             0xab, 0xcd, 0xef, 0x43,
                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    TestParser<crypto::BigEndian> parser(input.cmem());
    data_u output = parser.parse_all();
    ASSERT_NE(nullptr, output);
    EXPECT_EQ(0x10, output->num1);
    EXPECT_EQ(0x21a3, output->num2);
    EXPECT_EQ(0x4477dd, output->num3);
    EXPECT_EQ(0xabcdef43, output->num4);
    EXPECT_EQ(0x1122334455667788, output->num5);
}

TEST(BaseParser, TestDataUnconsumed) {
    crypto::bytestring input{0x10,
                             0x21, 0xa3,
                             0x44, 0x77, 0xdd,
                             0xab, 0xcd, 0xef, 0x43,
                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                             0x00};
    TestParser<crypto::LittleEndian> parser(input.cmem());
    data_u output = parser.parse_all();
    ASSERT_EQ(nullptr, output);
}

TEST(BaseParser, TestDataShortBy1) {
    crypto::bytestring input{0x10,
                             0x21, 0xa3,
                             0xab, 0xcd, 0xef, 0x43,
                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    TestParser<crypto::BigEndian> parser(input.cmem());
    data_u output = parser.parse();
    ASSERT_EQ(nullptr, output);
}

TEST(BaseParser, TestDataShortByField) {
    crypto::bytestring input{0x10,
                             0x21, 0xa3,
                             0xab, 0xcd, 0xef, 0x43};
    TestParser<crypto::BigEndian> parser(input.cmem());
    data_u output = parser.parse();
    ASSERT_EQ(nullptr, output);
}

TEST(BaseParser, TestDataEmpty) {
    crypto::bytestring input;
    TestParser<crypto::BigEndian> parser(input.cmem());
    data_u output = parser.parse();
    ASSERT_EQ(nullptr, output);
}

struct string_data {
    crypto::bytestring str1;
    crypto::bytestring str2;
    crypto::bytestring str3;
};
typedef std::unique_ptr<string_data> string_data_u;

class StringParser
    : public crypto::BaseParser<string_data, crypto::LittleEndian> {
  protected:
    virtual string_data_u parse_core() override {
        string_data_u out(new string_data);
        out->str1 = read_uint8_length_prefixed();
        out->str2 = read_uint16_length_prefixed();
        out->str3 = read_uint24_length_prefixed();
        return out;
    }

  public:
    StringParser(const crypto::memslice input)
        : crypto::BaseParser<string_data, crypto::LittleEndian>(input) {}
    virtual ~StringParser() {};
};

TEST(StringParser, EmptyStrings) {
    crypto::bytestring input{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    StringParser parser(input.cmem());
    string_data_u output = parser.parse_all();
    ASSERT_NE(nullptr, output);
    EXPECT_EQ(crypto::bytestring(), output->str1);
    EXPECT_EQ(crypto::bytestring(), output->str2);
    EXPECT_EQ(crypto::bytestring(), output->str3);
}

TEST(StringParser, NonEmptyString) {
    crypto::bytestring input{0x02, /* = */ 0xaa, 0xbb,
                             0x03, 0x00, /* = */ 0x11, 0x22, 0x33,
                             0x04, 0x00, 0x00, /* = */ 0x33, 0x55, 0xdd, 0xff};
    StringParser parser(input.cmem());
    string_data_u output = parser.parse_all();
    ASSERT_NE(nullptr, output);
    EXPECT_EQ(crypto::bytestring({0xaa, 0xbb}), output->str1);
    EXPECT_EQ(crypto::bytestring({0x11, 0x22, 0x33}), output->str2);
    EXPECT_EQ(crypto::bytestring({0x33, 0x55, 0xdd, 0xff}), output->str3);
}

class BoundedStringParser
    : public crypto::BaseParser<crypto::bytestring, crypto::LittleEndian> {
  protected:
    virtual crypto::bytestring_u parse_core() override {
        return crypto::bytestring_u(new crypto::bytestring(
                    read_uint8_length_prefixed(1, 2)));
    }

  public:
    BoundedStringParser(const crypto::memslice input)
        : crypto::BaseParser<crypto::bytestring, crypto::LittleEndian>(input) {}
    virtual ~BoundedStringParser() {};
};

TEST(BoundedStringParser, EmptyString) {
    crypto::bytestring input{0x00};
    BoundedStringParser parser(input.cmem());
    crypto::bytestring_u output = parser.parse();
    ASSERT_EQ(nullptr, output);
}

TEST(BoundedStringParser, LongString) {
    crypto::bytestring input{0x03, 0xaa, 0xbb, 0xcc};
    BoundedStringParser parser(input.cmem());
    crypto::bytestring_u output = parser.parse();
    ASSERT_EQ(nullptr, output);
}

TEST(BoundedStringParser, ValidString) {
    crypto::bytestring input{0x02, 0xab, 0xcd};
    BoundedStringParser parser(input.cmem());
    crypto::bytestring_u output = parser.parse();
    ASSERT_NE(nullptr, output);
    EXPECT_EQ(crypto::bytestring({0xab, 0xcd}), *output);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
