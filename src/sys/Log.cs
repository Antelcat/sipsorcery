//----------------------------------------------------------------------------
// File Name: Log.cs
// 
// Description: 
// Log provides a one stop shop for log settings rather then have configuration 
// functions in separate classes.
//
// Author(s):
// Aaron Clauson
//
// History:
// 04 Nov 2004	Aaron Clauson   Created.
// 14 Sep 2019  Aaron Clauson   Added NetStandard support.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//----------------------------------------------------------------------------

using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace SIPSorcery.Sys;

internal static class Log
{
    private const string LOG_CATEGORY = "sipsorcery";

    static Log()
    {
        LogFactory.Instance.OnFactorySet += Reset;
        logger = new DebugLogger();
    }

    private static ILogger? logger;
        
    internal static ILogger Logger
    {
        get => logger ??= LogFactory.CreateLogger(LOG_CATEGORY);
        set => logger = value;
    }

    /// <summary>
    /// Intended to be called if the application wide logging configuration changes. Will force
    /// the singleton logger to be re-created.
    /// </summary>
    internal static void Reset()
    {
        logger = null;
    }

    private class DebugLogger : ILogger
    {
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Debug.WriteLine($"[{LOG_CATEGORY}] {formatter(state, exception)}");
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return null;
        }
    }
}