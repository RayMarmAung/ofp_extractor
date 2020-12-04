#ifndef OFPEXTRACT_H
#define OFPEXTRACT_H

#include <QtCore>
#include <QObject>

struct OFP_KEY
{
    QString ver;
    QString mc;
    QString userkey;
    QString ivec;
};
struct OFP_MTK_HDR
{
    char        projName[48];
    uint64_t    unknown;
    uint32_t    reserved;
    char        cpuType[7];
    char        flashType[5];
    uint16_t    entriesCount;
    char        projInfo[32];
    uint16_t    chksum;
};
struct OFP_MTK_ENTRY_HDR
{
    char        name[32];
    uint64_t    offset;
    uint64_t    length;
    uint64_t    encLength;
    char        filename[32];
    uint64_t    chksum;
};

class OfpExtract : public QObject
{
public:
    OfpExtract();

    int generateKey2(QString filename, uint32_t &pageSize, QByteArray &key, QByteArray &iv, QByteArray &data);

    int extractXml(QString filename, QByteArray key, QByteArray iv, uint32_t &pageSize, QByteArray &data);

    int decryptData(QByteArray &data, QByteArray key, QByteArray iv);

    int parseProg(QByteArray data, uint32_t pageSize, QByteArray key, QByteArray iv, QString source, QString path);

    int parseFirmware(QByteArray data, uint32_t pageSize, QByteArray key, QByteArray iv, QString source, QString path);

    int decryptFile(QByteArray key, QByteArray iv, QString source, QString path, QString filename,
                    uint64_t start, uint64_t length, uint64_t rlength, uint64_t decryptSize = 0x40000);


    int bruteKey(QString filename, QByteArray &key, QByteArray &iv);
    int getInfo(QString filename);
    void mtkshuffle(QByteArray key, int keyLength, QByteArray &data, int inputLength);
    void mtkShuffle2(QByteArray key, int keyLength, QByteArray &data, int inputLength);


};

#endif // OFPEXTRACT_H
