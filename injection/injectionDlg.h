// injectionDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"

// CinjectionDlg 对话框
class CinjectionDlg : public CDialogEx
{
    // 构造
public:
    CinjectionDlg(CWnd* pParent = NULL);    // 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_INJECTION_DIALOG };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
    HICON m_hIcon;

    // 生成的消息映射函数
    virtual BOOL OnInitDialog();
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    DECLARE_MESSAGE_MAP()
private:
    // 进程列表控件
    CListCtrl process_list_ctrl_;
    int pid_ = -1;
private:
    void OnInitCtrl();
    void EnumProcessList();
    int GetSelectedItem(CListCtrl* list_ctrl);
    bool IsWow64Process(DWORD pid);
    bool Inject(DWORD pId, const CString& path_name);
public:
    afx_msg void OnRclickProcessList(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnAInject();
};
