using CodeSigner.Windows.Readiness;

namespace CodeSigner.Windows.Tests;

public sealed class WindowsInstallerProductSourceTests
{
    [Fact]
    public void ProductInfoUsesLengthProbeThenExactBufferForEveryProperty()
    {
        RecordingWindowsInstallerApi api = new();

        IReadOnlyList<WindowsInstallerProductRegistration> result =
            new WindowsInstallerProductSource(api).FindRelatedProducts(SimplySignInstallationProbe.ObservedUpgradeCode);

        WindowsInstallerProductRegistration registration = Assert.Single(result);
        Assert.Equal(SimplySignInstallationProbe.ObservedProductName, registration.ProductName);
        Assert.Equal(SimplySignInstallationProbe.ObservedPublisher, registration.Publisher);
        Assert.Equal(SimplySignInstallationProbe.ObservedVersion, registration.Version);
        Assert.All(api.PropertyCalls.GroupBy(call => call.PropertyName), calls =>
        {
            Assert.Equal(2, calls.Count());
            Assert.Null(calls.First().Buffer);
            Assert.NotNull(calls.Last().Buffer);
            Assert.Equal(calls.First().ReportedLength + 1, (uint)calls.Last().Buffer!.Length);
        });
    }

    [Fact]
    public void MalformedSecondBufferResponseDoesNotCreateRegistration()
    {
        RecordingWindowsInstallerApi api = new() { FailPublisherBufferCall = true };

        IReadOnlyList<WindowsInstallerProductRegistration> result =
            new WindowsInstallerProductSource(api).FindRelatedProducts(SimplySignInstallationProbe.ObservedUpgradeCode);

        Assert.Empty(result);
    }

    private sealed class RecordingWindowsInstallerApi : IWindowsInstallerApi
    {
        private const uint ErrorSuccess = 0;
        private const uint ErrorMoreData = 234;
        private const uint ErrorNoMoreItems = 259;
        private const uint ErrorInvalidData = 13;

        public bool FailPublisherBufferCall { get; init; }
        public List<PropertyCall> PropertyCalls { get; } = [];

        public uint EnumRelatedProducts(
            string upgradeCode,
            uint reserved,
            uint productIndex,
            char[] productCode)
        {
            if (productIndex > 0)
            {
                return ErrorNoMoreItems;
            }

            "{5394C22A-6EC6-4910-8A32-7C411EE290DF}\0".CopyTo(0, productCode, 0, productCode.Length);
            return ErrorSuccess;
        }

        public uint GetProductInfo(string productCode, string propertyName, char[]? value, ref uint valueLength)
        {
            string propertyValue = propertyName switch
            {
                "ProductName" => SimplySignInstallationProbe.ObservedProductName,
                "Publisher" => SimplySignInstallationProbe.ObservedPublisher,
                "VersionString" => SimplySignInstallationProbe.ObservedVersion,
                _ => throw new InvalidOperationException(propertyName)
            };
            if (value is null)
            {
                valueLength = checked((uint)propertyValue.Length);
                PropertyCalls.Add(new(propertyName, null, valueLength));
                return ErrorMoreData;
            }

            PropertyCalls.Add(new(propertyName, value, valueLength));
            if (FailPublisherBufferCall && propertyName == "Publisher")
            {
                return ErrorInvalidData;
            }

            propertyValue.CopyTo(0, value, 0, propertyValue.Length);
            valueLength = checked((uint)propertyValue.Length);
            return ErrorSuccess;
        }
    }

    private sealed record PropertyCall(string PropertyName, char[]? Buffer, uint ReportedLength);
}
