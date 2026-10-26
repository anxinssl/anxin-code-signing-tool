using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace CodeSigner.App.Tests;

internal static class FileTaskQueueEvidenceSerializer
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public static string Serialize(object value) => JsonSerializer.Serialize(value, IndentedJson);
}

internal static class FileTaskQueueTelemetrySerializationContract
{
    private static readonly HashSet<Type> UnsupportedRuntimeTypes =
    [
        typeof(IntPtr),
        typeof(UIntPtr),
        typeof(HandleRef),
        typeof(Type)
    ];

    public static NativeInputDeliveryTrace CreateRepresentativeTelemetry() => new(
        "Down",
        "None",
        "SendInputOnTargetDispatcherThread",
        0x1234L,
        0xDEF0U,
        0x5678L,
        0x1357U,
        0x2468U,
        42,
        false,
        false,
        true,
        0x9ABCL,
        "QueueGrid",
        true,
        1U,
        1U,
        0,
        true,
        "None",
        true,
        "None",
        new SelectionTrace(
            "item-1",
            ["item-1"],
            "QueueGrid",
            nameof(System.Windows.Controls.DataGridCell),
            true,
            "item-1",
            0,
            true),
        new RoutedKeyEventTrace(
            nameof(System.Windows.Controls.DataGridCell),
            nameof(System.Windows.Controls.DataGridCell),
            false,
            false,
            nameof(System.Windows.Controls.DataGridCell),
            nameof(System.Windows.Controls.DataGridCell),
            true,
            true,
            true,
            "None",
            true),
        new SelectionTrace(
            "item-2",
            ["item-2"],
            "QueueGrid",
            nameof(System.Windows.Controls.DataGridCell),
            true,
            "item-2",
            0,
            true),
        new NativeInputCleanupTrace("Down", "None", 1U, 1U, 0, true, true));

    public static UiEventTimelineTrace CreateRepresentativeTimelineEntry() => new(
        1,
        123456789,
        "RouteKey:Down:None:send-input",
        "GotKeyboardFocus",
        nameof(System.Windows.Controls.DataGrid),
        nameof(System.Windows.Controls.DataGridCell),
        "QueueRow_1",
        nameof(System.Windows.Controls.DataGridCell),
        "QueueRow_2",
        nameof(System.Windows.Controls.DataGridCell),
        "QueueRow_2",
        nameof(System.Windows.Controls.DataGridCell),
        true,
        "item-2",
        ["item-2"],
        "item-2",
        0,
        true,
        "");

    public static void AssertPersistedTelemetryTypes(IEnumerable<NativeInputDeliveryTrace> telemetry)
    {
        AssertSupportedType(typeof(IReadOnlyCollection<NativeInputDeliveryTrace>), "inputTelemetry");
        foreach (NativeInputDeliveryTrace entry in telemetry)
        {
            AssertSupportedType(entry.GetType(), "inputTelemetry[]");
        }
    }

    public static void AssertPersistedTimelineTypes(IEnumerable<UiEventTimelineTrace> timeline)
    {
        AssertSupportedType(typeof(IReadOnlyCollection<UiEventTimelineTrace>), "uiEventTimeline");
        foreach (UiEventTimelineTrace entry in timeline)
        {
            AssertSupportedType(entry.GetType(), "uiEventTimeline[]");
        }
    }

    private static void AssertSupportedType(Type type, string path)
    {
        Type normalized = Nullable.GetUnderlyingType(type) ?? type;
        if (UnsupportedRuntimeTypes.Contains(normalized) ||
            typeof(Delegate).IsAssignableFrom(normalized) ||
            typeof(SafeHandle).IsAssignableFrom(normalized))
        {
            throw new InvalidDataException($"Unsupported persisted telemetry type {normalized.FullName} at {path}.");
        }

        if (normalized.IsPrimitive || normalized.IsEnum || normalized == typeof(string) || normalized == typeof(decimal))
        {
            return;
        }

        if (normalized.IsArray)
        {
            AssertSupportedType(normalized.GetElementType()!, path + "[]");
            return;
        }

        if (normalized.IsGenericType &&
            (normalized.GetGenericTypeDefinition() == typeof(IEnumerable<>) ||
             normalized.GetGenericTypeDefinition() == typeof(IReadOnlyCollection<>) ||
             normalized.GetGenericTypeDefinition() == typeof(IReadOnlyList<>) ||
             normalized.GetGenericTypeDefinition() == typeof(List<>)))
        {
            AssertSupportedType(normalized.GetGenericArguments()[0], path + "[]");
            return;
        }

        foreach (PropertyInfo property in normalized.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            if (property.GetMethod is null || property.GetIndexParameters().Length != 0)
            {
                continue;
            }

            AssertSupportedType(property.PropertyType, path + "." + property.Name);
        }
    }
}

internal sealed record SelectionTrace(
    string? CurrentItemId,
    string[] SelectedItemIds,
    string? FocusedAutomationId,
    string? FocusedElementType,
    bool QueueHasKeyboardFocus,
    string? CurrentCellItemId,
    int? CurrentCellColumnDisplayIndex,
    bool CurrentCellIsValid);

internal sealed record RoutedKeyEventTrace(
    string? PreviewSourceType,
    string? PreviewOriginalSourceType,
    bool PreviewHandledAtWindow,
    bool PreviewHandledAtGridAfterClassHandler,
    string? KeyDownSourceType,
    string? KeyDownOriginalSourceType,
    bool KeyDownHandledAtGridAfterClassHandler,
    bool KeyDownHandledAtWindowAfterClassHandler,
    bool KeyUpReceived,
    string? KeyUpModifiers,
    bool KeyUpHandledAtWindow);

internal sealed record NativeInputCleanupTrace(
    string Key,
    string Modifiers,
    uint ChordEventsInserted,
    uint CleanupEventsInserted,
    int CleanupLastError,
    bool PrimaryKeyReleased,
    bool ModifiersReleased);

internal sealed record NativeInputDeliveryTrace(
    string Key,
    string RequestedModifiers,
    string Mechanism,
    long ForegroundHwnd,
    uint ForegroundThreadId,
    long TargetWindowHwnd,
    uint TargetWindowThreadId,
    uint TargetDispatcherThreadId,
    int TargetDispatcherManagedThreadId,
    bool InputThreadsAttached,
    bool InputThreadAttachmentApplicable,
    bool SetForegroundWindowAccepted,
    long NativeFocusHwndBeforeInput,
    string? FocusedAutomationIdBeforeInput,
    bool QueueHadKeyboardFocusBeforeInput,
    uint SendInputRequestedCount,
    uint SendInputAcceptedCount,
    int SendInputLastError,
    bool PreviewKeyDownReceived,
    string? PreviewKeyDownModifiers,
    bool KeyDownReceived,
    string? KeyDownModifiers,
    SelectionTrace BeforeInput,
    RoutedKeyEventTrace RoutedEvents,
    SelectionTrace? AfterProcessing,
    NativeInputCleanupTrace Cleanup);

internal sealed record UiEventTimelineTrace(
    long Order,
    long StopwatchTimestamp,
    string Phase,
    string EventName,
    string? SourceType,
    string? OriginalSourceType,
    string? OldFocusAutomationId,
    string? OldFocusElementType,
    string? NewFocusAutomationId,
    string? NewFocusElementType,
    string? FocusedAutomationId,
    string? FocusedElementType,
    bool QueueHasKeyboardFocus,
    string? CurrentItemId,
    string[] SelectedItemIds,
    string? CurrentCellItemId,
    int? CurrentCellColumnDisplayIndex,
    bool CurrentCellIsValid,
    string FocusTargetAutomationId);
