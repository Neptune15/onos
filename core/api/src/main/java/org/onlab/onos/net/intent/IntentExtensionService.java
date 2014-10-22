/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.onlab.onos.net.intent;

import java.util.Map;

/**
 * Service for extending the capability of intent framework by
 * adding additional compilers or/and installers.
 */
public interface IntentExtensionService {
    /**
     * Registers the specified compiler for the given intent class.
     *
     * @param cls      intent class
     * @param compiler intent compiler
     * @param <T>      the type of intent
     */
    <T extends Intent> void registerCompiler(Class<T> cls, IntentCompiler<T> compiler);

    /**
     * Unregisters the compiler for the specified intent class.
     *
     * @param cls intent class
     * @param <T> the type of intent
     */
    <T extends Intent> void unregisterCompiler(Class<T> cls);

    /**
     * Returns immutable set of bindings of currently registered intent compilers.
     *
     * @return the set of compiler bindings
     */
    Map<Class<? extends Intent>, IntentCompiler<? extends Intent>> getCompilers();

    /**
     * Registers the specified installer for the given installable intent class.
     *
     * @param cls       installable intent class
     * @param installer intent installer
     * @param <T>       the type of installable intent
     */
    <T extends Intent> void registerInstaller(Class<T> cls, IntentInstaller<T> installer);

    /**
     * Unregisters the installer for the given installable intent class.
     *
     * @param cls installable intent class
     * @param <T> the type of installable intent
     */
    <T extends Intent> void unregisterInstaller(Class<T> cls);

    /**
     * Returns immutable set of bindings of currently registered intent installers.
     *
     * @return the set of installer bindings
     */
    Map<Class<? extends Intent>, IntentInstaller<? extends Intent>> getInstallers();
}
