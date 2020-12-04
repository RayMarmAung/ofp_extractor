#include "ofpextract.h"
#include "aes.h"
#include "pem.h"
#include "rsa.h"
#include <QCryptographicHash>

int ROR(int x, int n, int bits = 32)
{
    int mask = pow(2,n) - 1;
    int maskBits = x & mask;
    return (x >> n) | (maskBits << (bits - n));
}
uint8_t ROL(int x, int n, int bits = 32)
{
    return ROR(x, bits - n, bits);
}

OfpExtract::OfpExtract()
{

}

int OfpExtract::generateKey2(QString filename, uint32_t &pageSize, QByteArray &key, QByteArray &iv, QByteArray &data)
{
    QVector<OFP_KEY> keys;
    {
        OFP_KEY key0 = {};
        {
            key0.ver = "V1.4.17/1.4.27";
            key0.mc = "27827963787265EF89D126B69A495A21";
            key0.userkey = "82C50203285A2CE7D8C3E198383CE94C";
            key0.ivec = "422DD5399181E223813CD8ECDF2E4D72";
        }
        keys.push_back(key0);

        OFP_KEY key1 = {};
        {
            key1.ver = "V1.5.13";
            key1.mc = "67657963787565E837D226B69A495D21";
            key1.userkey = "F6C50203515A2CE7D8C3E1F938B7E94C";
            key1.ivec = "42F2D5399137E2B2813CD8ECDF2F4D72";
        }
        keys.push_back(key1);

        OFP_KEY key2 = {};
        {
            key2.ver = "V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6";
            key2.mc = "3C2D518D9BF2E4279DC758CD535147C3";
            key2.userkey = "87C74A29709AC1BF2382276C4E8DF232";
            key2.ivec = "598D92E967265E9BCABE2469FE4A915E";
        }
        keys.push_back(key2);

        OFP_KEY key3 = {};
        {
            key3.ver = "V1.6.17";
            key3.mc = "E11AA7BB558A436A8375FD15DDD4651F";
            key3.userkey = "77DDF6A0696841F6B74782C097835169";
            key3.ivec = "A739742384A44E8BA45207AD5C3700EA";
        }
        keys.push_back(key3);

        OFP_KEY key4 = {};
        {
            key4.ver = "V1.7.2";
            key4.mc = "8FB8FB261930260BE945B841AEFA9FD4";
            key4.userkey = "E529E82B28F5A2F8831D860AE39E425D";
            key4.ivec = "8A09DA60ED36F125D64709973372C1CF";
        }
        keys.push_back(key4);
    }

    int ret;

    for (OFP_KEY dkey : keys)
    {
        key.clear();
        iv.clear();

        QByteArray mc = QByteArray::fromHex(dkey.mc.toUtf8());
        QByteArray userkey = QByteArray::fromHex(dkey.userkey.toUtf8());
        QByteArray ivec = QByteArray::fromHex(dkey.ivec.toUtf8());

        for (int i = 0; i < userkey.length(); i++)
        {
            uint8_t v = ROL((uint8_t)userkey.at(i)^(uint8_t)mc.at(i), 4, 8);
            key.append(v);
        }

        for (int i = 0; i < userkey.length(); i++)
        {
            uint8_t v = ROL((uint8_t)ivec.at(i)^(uint8_t)mc.at(i), 4, 8);
            iv.append(v);
        }

        key = QCryptographicHash::hash(key, QCryptographicHash::Md5);
        iv = QCryptographicHash::hash(iv, QCryptographicHash::Md5);

        key = key.toHex().toLower().mid(0, 16);
        iv = iv.toHex().toLower().mid(0, 16);

        ret = extractXml(filename, key, iv, pageSize, data);
        if (ret == 0)
            return 0;
        if (ret == -2)
            return -2;
    }

    return ret;
}
int OfpExtract::extractXml(QString filename, QByteArray key, QByteArray iv, uint32_t &pageSize, QByteArray &data)
{
    QFile file(filename);

    uint64_t fileSize = file.size();
    if (fileSize <= 0)
        return -2;

    if (file.open(QFile::ReadOnly))
    {
        pageSize = 512;
        uint64_t xmlOffset = fileSize - pageSize;
        file.seek(xmlOffset + 16);

        uint32_t check = 0;
        QByteArray tmpData = file.read(4);
        memcpy(&check, tmpData.data(), sizeof(uint32_t));

        if (check != 0x7cef)
        {
            pageSize = 4096;
            xmlOffset = fileSize - pageSize;
            file.seek(xmlOffset + 16);

            check = 0;
            tmpData = file.read(4);
            memcpy(&check, tmpData.data(), sizeof(uint32_t));

            if (check != 0x7cef)
                return -1;
        }

        uint64_t offset = 0;
        tmpData = file.read(4);
        memcpy(&offset, tmpData.data(), sizeof(uint32_t));
        offset *= pageSize;

        uint64_t length = 0;
        tmpData = file.read(4);
        memcpy(&length, tmpData.data(), sizeof(uint32_t));

        file.seek(offset);
        data = file.read(length);
        if (length % 16)
            data.append(16-(length%16), '\x00');

        decryptData(data, key, iv);

        if (data.startsWith("<?xml"))
            return 0;
        else
            return -1;
    }

    return -2;
}
int OfpExtract::decryptData(QByteArray &data, QByteArray key, QByteArray iv)
{
    QByteArray output;
    AES_KEY aes_key;
    int read, pos = 0;
    unsigned char outBuff[4096];

    AES_set_encrypt_key((const unsigned char*)key.constData(), 128, &aes_key);

    qint64 length = data.length();
    qint64 startAdd = 0;

    while (length > 0)
    {
        read = qMin(length, (qint64)4096);
        AES_cfb128_encrypt((unsigned char*)data.mid(startAdd, read).data(),
                           outBuff, read, &aes_key, (unsigned char*)iv.data(), &pos, AES_DECRYPT);
        output.append((char*)outBuff, read);
        length -= read;
        startAdd += read;
    }

    data = output;

    return 0;
}
int OfpExtract::parseProg(QByteArray data, uint32_t pageSize, QByteArray key, QByteArray iv,
                         QString source, QString path)
{
    QString fileName;
    uint64_t start = 0, length = 0, rlength = 0;

    QXmlStreamReader reader(data);
    while (!reader.atEnd())
    {
        if (reader.readNext() == QXmlStreamReader::StartDocument)
            continue;
        if (reader.name().toString().compare("sahara", Qt::CaseInsensitive) == 0)
        {
            while (reader.readNextStartElement())
            {
                if (reader.name().toString().compare("file", Qt::CaseInsensitive) == 0)
                {
                    for (const QXmlStreamAttribute &attr : reader.attributes())
                    {
                        if (attr.name().toString().compare("path", Qt::CaseInsensitive) == 0)
                            fileName = attr.value().toString();
                        else if (attr.name().toString().compare("fileoffsetinsrc", Qt::CaseInsensitive) == 0)
                            start = attr.value().toULongLong() * pageSize;
                        else if (attr.name().toString().compare("sizeinsectorinsrc", Qt::CaseInsensitive) == 0)
                            length = attr.value().toULongLong() * pageSize;
                        else if (attr.name().toString().compare("sizeinbyteinsrc", Qt::CaseInsensitive) == 0)
                            rlength = attr.value().toULongLong();
                    }
                }
            }
        }
    }

    if (length <= 0 || rlength <= 0)
        return -1;

    return decryptFile(key, iv, source, path, fileName, start, length, rlength, rlength);
}
int OfpExtract::parseFirmware(QByteArray data, uint32_t pageSize, QByteArray key, QByteArray iv,
                              QString source, QString path)
{
    QString fileName;
    uint64_t start = 0, length = 0, rlength = 0;

    QXmlStreamReader reader(data);
    while (!reader.atEnd())
    {
        if (reader.readNext() == QXmlStreamReader::StartDocument)
            continue;
        if (reader.name().toString().compare("program", Qt::CaseInsensitive) == 0)
        {
            fileName = "";
            for (const QXmlStreamAttribute &attr : reader.attributes())
            {
                if (attr.name().toString().compare("filename", Qt::CaseInsensitive) == 0)
                    fileName = attr.value().toString();
                else if (attr.name().toString().compare("fileoffsetinsrc", Qt::CaseInsensitive) == 0)
                    start = attr.value().toULongLong() * pageSize;
                else if (attr.name().toString().compare("sizeinsectorinsrc", Qt::CaseInsensitive) == 0)
                    length = attr.value().toULongLong() * pageSize;
                else if (attr.name().toString().compare("sizeinbyteinsrc", Qt::CaseInsensitive) == 0)
                    rlength = attr.value().toULongLong();
            }

            if (fileName.isEmpty())
                continue;

            int ret = decryptFile(key, iv, source, path, fileName, start, length, rlength);
            if (ret != 0)
                return ret;
        }
    }

    return 0;
}
int OfpExtract::decryptFile(QByteArray key, QByteArray iv, QString source, QString path, QString filename,
                            uint64_t start, uint64_t length, uint64_t rlength, uint64_t decryptSize)
{
    QFile srcFile(source);
    QFile targetFile(path + "/" + filename);

    QDir dir(path);
    if (!dir.exists())
        dir.mkdir(".");

    if (!srcFile.open(QFile::ReadOnly))
        return -1;
    if (!targetFile.open(QFile::WriteOnly))
        return -1;

    srcFile.seek(start);
    uint64_t size = 0;
    if (length > decryptSize)
        size = decryptSize;
    else
        size = length;

    QByteArray data = srcFile.read(size);
    if (size % 16)
        data.append(16-(size%16), '\x00');

    if (decryptData(data, key, iv) != 0)
        return -1;

    if (size == decryptSize)
    {
        targetFile.write(data.mid(0, size));

        if (rlength > size)
        {
            rlength -= size;
            if (rlength > 0)
            {
                srcFile.seek(start+decryptSize);
                uint64_t rlen = 0;
                uint64_t sz = 0;
                while (rlength > 0)
                {
                    if (rlength < 0x100000)
                        sz = rlength;
                    else
                        sz = 0x100000;
                    data = srcFile.read(sz);
                    targetFile.write(data);
                    rlen += data.length();
                    rlength -= sz;
                }
            }
        }
    }
    else
    {
        targetFile.write(data.mid(0, rlength));
    }

    return 0;
}

int OfpExtract::bruteKey(QString filename, QByteArray &key, QByteArray &iv)
{
    QVector<OFP_KEY> keys;
    {
        OFP_KEY key0 = {};
        {
            key0.ver = "V1.5.13";
            key0.mc = "67657963787565E837D226B69A495D21";
            key0.userkey = "F6C50203515A2CE7D8C3E1F938B7E94C";
            key0.ivec = "42F2D5399137E2B2813CD8ECDF2F4D72";
        }
        keys.push_back(key0);

        OFP_KEY key1 = {};
        {
            key1.ver = "V1.4.17/1.4.27";
            key1.mc = "9E4F32639D21357D37D226B69A495D21";
            key1.userkey = "A3D8D358E42F5A9E931DD3917D9A3218";
            key1.ivec = "386935399137416B67416BECF22F519A";
        }
        keys.push_back(key1);

        OFP_KEY key2 = {};
        {
            key2.ver = "V1.6.17";
            key2.mc = "892D57E92A4D8A975E3C216B7C9DE189";
            key2.userkey = "D26DF2D9913785B145D18C7219B89F26";
            key2.ivec = "516989E4A1BFC78B365C6BC57D944391";
        }
        keys.push_back(key2);

        OFP_KEY key3 = {};
        {
            key3.ver = "V1.7.2";
            key3.mc = "27827963787265EF89D126B69A495A21";
            key3.userkey = "82C50203285A2CE7D8C3E198383CE94C";
            key3.ivec = "422DD5399181E223813CD8ECDF2E4D72";
        }
        keys.push_back(key3);

        OFP_KEY key4 = {};
        {
            key4.ver = "V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6";
            key4.mc = "3C4A618D9BF2E4279DC758CD535147C3";
            key4.userkey = "87B13D29709AC1BF2382276C4E8DF232";
            key4.ivec = "59B7A8E967265E9BCABE2469FE4A915E";
        }
        keys.push_back(key4);

        OFP_KEY key5 = {};
        {
            key5.ver = "V1.7.2";
            key5.mc = "1C3288822BF824259DC852C1733127D3";
            key5.userkey = "E7918D22799181CF2312176C9E2DF298";
            key5.ivec = "3247F889A7B6DECBCA3E28693E4AAAFE";
        }
        keys.push_back(key5);

        OFP_KEY key6 = {};
        {
            key6.ver = "V1.7.2";
            key6.mc = "1E4F32239D65A57D37D2266D9A775D43";
            key6.userkey = "A332D3C3E42F5A3E931DD991729A321D";
            key6.ivec = "3F2A35399A373377674155ECF28FD19A";
        }
        keys.push_back(key6);

        OFP_KEY key7 = {};
        {
            key7.ver = "V1.7.2";
            key7.mc = "122D57E92A518AFF5E3C786B7C34E189";
            key7.userkey = "DD6DF2D9543785674522717219989FB0";
            key7.ivec = "12698965A132C76136CC88C5DD94EE91";
        }
        keys.push_back(key7);

    }

    QFile file(filename);
    if (!file.open(QFile::ReadOnly))
        return -1;

    QByteArray encData;

    //QByteArray key, iv;

    for (OFP_KEY dkey : keys)
    {
        file.seek(0);
        encData = file.read(16);

        key.clear();
        iv.clear();

        QByteArray obsKey = QByteArray::fromHex(dkey.mc.toUtf8());
        QByteArray encAesKey = QByteArray::fromHex(dkey.userkey.toUtf8());
        QByteArray encAesIv = QByteArray::fromHex(dkey.ivec.toUtf8());

        mtkShuffle2(obsKey, 16, encAesKey, 16);
        mtkShuffle2(obsKey, 16, encAesIv, 16);

        key = QCryptographicHash::hash(encAesKey, QCryptographicHash::Md5).toHex().left(16);
        iv = QCryptographicHash::hash(encAesIv, QCryptographicHash::Md5).toHex().left(16);

        decryptData(encData, key, iv);

        if (encData.startsWith("MMM"))
            return 0;
    }
    return -1;
}
int OfpExtract::getInfo(QString filename)
{
    QFile file(filename);
    if (!file.open(QFile::ReadOnly))
        return -1;

    uint32_t hdrLength = 0x6c;
    file.seek(file.size() - hdrLength);
    QByteArray hdrKey("geyixue");
    QByteArray input = file.read(hdrLength);

    mtkshuffle(hdrKey, hdrKey.length(), input, hdrLength);

    OFP_MTK_HDR hdr;
    memcpy(&hdr, input.data(), sizeof(hdr));

    uint32_t entriesLen = hdr.entriesCount * 0x60;
    file.seek(file.size() - entriesLen - hdrLength);

    input = file.read(entriesLen);

    mtkshuffle(hdrKey, hdrKey.length(), input, entriesLen);

    QFile test("test.bin");
    if (test.open(QFile::WriteOnly))
    {
        test.write(input);
        test.close();
    }

    qDebug() << "OK";
}
void OfpExtract::mtkshuffle(QByteArray key, int keyLength, QByteArray &data, int inputLength)
{
    for (int i = 0; i < inputLength; i++)
    {
        uint8_t k = key.at(i % keyLength);
        uint8_t h = ((data.at(i) & 0xf0) >> 4) | (16 * (data.at(i) & 0xf));
        data[i] = (uint8_t)k ^ (uint8_t)h;
    }
}
void OfpExtract::mtkShuffle2(QByteArray key, int keyLength, QByteArray &data, int inputLength)
{
    for (int i = 0; i < inputLength; i++)
    {
        uint8_t tmp = key.at(i%keyLength) ^ data.at(i);
        data[i] = (uint8_t)(((tmp & 0xf0) >> 4) | (16 * (tmp & 0xf)));
    }
}
