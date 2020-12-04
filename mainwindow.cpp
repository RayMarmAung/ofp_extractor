#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include "ofpextract.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    QString path = QFileDialog::getOpenFileName(this, "Open File", QString(), "ofp file (*.ofp)");
    if (path.isEmpty())
        return;
    ui->lineEdit->setText(path);
}

void MainWindow::on_pushButton_2_clicked()
{
    if (ui->lineEdit->text().isEmpty())
        return;
    QString filename = ui->lineEdit->text();

    uint32_t pageSize = 0;
    QByteArray key, iv, data;
    OfpExtract extract;
    QString path;

    // qualcomm
    int ret = extract.generateKey2(filename, pageSize, key, iv, data);
    if (ret == 0)
    {
        data = data.mid(0, data.lastIndexOf(">")+1);
        path = QFileInfo(filename).absolutePath() + "/extract2";

        ret = extract.parseProg(data, pageSize, key, iv, filename, path);
        ret = extract.parseFirmware(data, pageSize, key, iv, filename, path);

        return;
    }

    ret = extract.bruteKey(filename, key, iv);
    if (ret == 0)
    {
        ret = extract.getInfo(filename);
    }

    qDebug() << "OK";
}
