#ifndef READONLYDELEGATE_H
#define READONLYDELEGATE_H

#include<QWidget>
#include<QItemDelegate>
#include<QStyleOptionViewItem>


//创建表格单元格的编辑器，由于该类实现的是只读的表格单元格，
//因此在该函数中返回了 NULL，表示不创建编辑器，从而实现了只读的效果。

/*
 * 利用qt委托去实现table框，数据只读，gui界面不可编辑的状态
*/
//new add
class readonlydelegate: public QItemDelegate
{
public:
    readonlydelegate(QWidget *parent = NULL):QItemDelegate(parent){}
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                            const QModelIndex &index) const override //final
    {
        Q_UNUSED(parent)
        Q_UNUSED(option)
        Q_UNUSED(index)
        return NULL;
    }
};

#endif // READONLYDELEGATE_H
