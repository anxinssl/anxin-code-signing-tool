using System.Windows;

namespace CodeSigner.App;

public partial class PrimitiveShowcaseWindow : Window
{
    private static readonly PrimitiveQueueRow[] SampleRows =
    [
        new(
            "library-sample",
            @"C:\release\sample-library.dll",
            "正在辅助签名",
            "60%",
            "等待验证"),
        new(
            "catalog-sample",
            @"C:\release\sample-catalog.cat",
            "待处理",
            "0%",
            "等待签名")
    ];

    public PrimitiveShowcaseWindow()
    {
        InitializeComponent();
        DataContext = SampleRows;
    }

    private sealed record PrimitiveQueueRow(string Id, string Path, string State, string Progress, string Result);
}
