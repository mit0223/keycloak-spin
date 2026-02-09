package com.keycloakspin.db;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Persistence;

public final class HibernateSchemaExport {
    private static final String ARG_OUTPUT = "--output";
    private static final String ARG_DIALECT = "--dialect";
    private static final String ARG_PERSISTENCE_UNIT = "--persistence-unit";
    private static final String DEFAULT_DIALECT = "org.hibernate.community.dialect.SQLiteDialect";

    private HibernateSchemaExport() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager");
        Map<String, String> parsed = parseArgs(args);
        String output = require(parsed, ARG_OUTPUT);
        String dialect = parsed.getOrDefault(ARG_DIALECT, DEFAULT_DIALECT);

        Config.init(new Config.SystemPropertiesConfigProvider());
        Profile.defaults();
        CryptoIntegration.init(HibernateSchemaExport.class.getClassLoader());

        PersistenceInfo persistenceInfo = preparePersistenceInfo(HibernateSchemaExport.class.getClassLoader());
        String persistenceUnit = parsed.get(ARG_PERSISTENCE_UNIT);
        if (persistenceUnit == null || persistenceUnit.isBlank()) {
            persistenceUnit = persistenceInfo.unitName;
        }

        Thread.currentThread().setContextClassLoader(persistenceInfo.classLoader);

        prepareOutputFile(output);

        Map<String, Object> properties = new HashMap<>();
        properties.put("jakarta.persistence.schema-generation.scripts.action", "create");
        properties.put("jakarta.persistence.schema-generation.scripts.create-target", output);
        properties.put("jakarta.persistence.schema-generation.database.action", "none");
        properties.put("jakarta.persistence.schema-generation.create-source", "metadata");
        properties.put("jakarta.persistence.jdbc.driver", "org.sqlite.JDBC");
        properties.put("jakarta.persistence.jdbc.url", "jdbc:sqlite::memory:");
        properties.put("hibernate.dialect", dialect);
        properties.put("hibernate.format_sql", "true");
        properties.put("hibernate.hbm2ddl.delimiter", ";");
        properties.put("hibernate.hbm2ddl.schema_generation.script.append", "false");

        EntityManagerFactory factory = Persistence.createEntityManagerFactory(persistenceUnit, properties);
        factory.close();
    }

    private static PersistenceInfo preparePersistenceInfo(ClassLoader classLoader) {
        try (InputStream persistenceXml = classLoader.getResourceAsStream("META-INF/persistence.xml")) {
            if (persistenceXml != null) {
                return new PersistenceInfo(findPersistenceUnitName(persistenceXml), classLoader);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load META-INF/persistence.xml", e);
        }

        try (InputStream defaultPersistence = classLoader.getResourceAsStream("default-persistence.xml")) {
            if (defaultPersistence == null) {
                throw new IllegalStateException("default-persistence.xml not found on classpath");
            }
            Path tempDir = Files.createTempDirectory("keycloak-persistence");
            Path metaInf = tempDir.resolve("META-INF");
            Files.createDirectories(metaInf);
            Path persistencePath = metaInf.resolve("persistence.xml");
            Files.copy(defaultPersistence, persistencePath, StandardCopyOption.REPLACE_EXISTING);

            String unitName;
            try (InputStream copied = Files.newInputStream(persistencePath)) {
                unitName = findPersistenceUnitName(copied);
            }

            URLClassLoader tempLoader = new URLClassLoader(new URL[] { tempDir.toUri().toURL() }, classLoader);
            return new PersistenceInfo(unitName, tempLoader);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to prepare persistence.xml", e);
        }
    }

    private static String findPersistenceUnitName(InputStream stream) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(stream);
            NodeList units = doc.getElementsByTagName("persistence-unit");
            if (units.getLength() == 0) {
                throw new IllegalStateException("No persistence-unit found in persistence.xml");
            }
            Element unit = (Element) units.item(0);
            String name = unit.getAttribute("name");
            if (name == null || name.isBlank()) {
                throw new IllegalStateException("persistence-unit name is missing");
            }
            return name;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read persistence-unit name", e);
        }
    }

    private static void prepareOutputFile(String output) {
        try {
            Path path = Paths.get(output);
            Files.deleteIfExists(path);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to prepare output file", e);
        }
    }

    private static final class PersistenceInfo {
        private final String unitName;
        private final ClassLoader classLoader;

        private PersistenceInfo(String unitName, ClassLoader classLoader) {
            this.unitName = unitName;
            this.classLoader = classLoader;
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> parsed = new HashMap<>();
        for (int i = 0; i < args.length; i += 2) {
            if (i + 1 >= args.length) {
                throw new IllegalArgumentException("Missing value for argument: " + args[i]);
            }
            parsed.put(args[i], args[i + 1]);
        }
        return parsed;
    }

    private static String require(Map<String, String> parsed, String key) {
        String value = parsed.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required argument: " + key);
        }
        return value;
    }
}
