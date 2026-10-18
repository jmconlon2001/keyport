using Keyport.Server;

// Fatal startup errors (missing/wrong master key, bad config) are reported and turned into exit code 1.
// Letting them escape would abort() the runtime, which as PID 1 in a container can hang instead of exiting.
try
{
    if (Cli.IsCommand(args))
        return await Cli.RunAsync(args);

    var app = KeyportApp.Build(args);
    await KeyportApp.InitializeAsync(app);
    await app.RunAsync();
    return 0;
}
catch (Exception ex) when (ex is not OperationCanceledException)
{
    Console.Error.WriteLine($"FATAL: Keyport could not start: {ex.Message}");
    Console.Error.WriteLine(ex);
    return 1;
}

public partial class Program;
