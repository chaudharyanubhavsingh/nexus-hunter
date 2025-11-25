#!/usr/bin/env python3
"""
Migration script to add advanced fields to existing targets table
Run this to add the new target fields without losing existing data
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.append(str(Path(__file__).parent))

from core.database import Database
from core.config import get_settings
from loguru import logger


async def migrate_targets_table():
    """Add new columns to the targets table"""
    
    settings = get_settings()
    await Database.connect()
    
    # SQL commands to add new columns
    migration_commands = [
        "ALTER TABLE targets ADD COLUMN priority VARCHAR(20) DEFAULT 'medium'",
        "ALTER TABLE targets ADD COLUMN max_depth INTEGER DEFAULT 5",
        "ALTER TABLE targets ADD COLUMN contact_email VARCHAR(255)",
        "ALTER TABLE targets ADD COLUMN rate_limit INTEGER DEFAULT 5", 
        "ALTER TABLE targets ADD COLUMN authentication_required BOOLEAN DEFAULT FALSE",
        "ALTER TABLE targets ADD COLUMN api_config JSON",
        "ALTER TABLE targets ADD COLUMN notes TEXT",
    ]
    
    logger.info("🔄 Starting targets table migration...")
    
    try:
        async with Database.engine.begin() as conn:
            for i, command in enumerate(migration_commands, 1):
                try:
                    logger.info(f"  [{i}/{len(migration_commands)}] {command}")
                    await conn.execute(text(command))
                    logger.info(f"  ✅ Column added successfully")
                except Exception as e:
                    if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                        logger.info(f"  ⚠️ Column already exists, skipping")
                    else:
                        logger.error(f"  ❌ Failed to add column: {e}")
                        raise
        
        logger.info("✅ Targets table migration completed successfully!")
        
        # Test the migration by querying the table structure
        async with Database.engine.begin() as conn:
            # Check if we can select from the table with new columns
            result = await conn.execute(text("SELECT priority, max_depth, contact_email, rate_limit, authentication_required, api_config, notes FROM targets LIMIT 1"))
            logger.info("✅ Migration validation: New columns are accessible")
            
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        return False
    
    finally:
        await Database.disconnect()
    
    return True


async def verify_migration():
    """Verify that the migration was successful"""
    
    await Database.connect()
    
    try:
        logger.info("🔍 Verifying migration...")
        
        async with Database.engine.begin() as conn:
            # Try to get table info
            if "sqlite" in get_settings().database_url:
                result = await conn.execute(text("PRAGMA table_info(targets)"))
                columns = await result.fetchall()
                column_names = [col[1] for col in columns]
            else:
                # PostgreSQL
                result = await conn.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'targets'
                """))
                columns = await result.fetchall()
                column_names = [col[0] for col in columns]
            
            # Check for new columns
            expected_new_columns = [
                'priority', 'max_depth', 'contact_email', 
                'rate_limit', 'authentication_required', 
                'api_config', 'notes'
            ]
            
            missing_columns = []
            for col in expected_new_columns:
                if col not in column_names:
                    missing_columns.append(col)
            
            if missing_columns:
                logger.error(f"❌ Missing columns: {missing_columns}")
                return False
            else:
                logger.info("✅ All new columns are present")
                logger.info(f"   Total columns: {len(column_names)}")
                logger.info(f"   New columns: {expected_new_columns}")
                return True
                
    except Exception as e:
        logger.error(f"❌ Verification failed: {e}")
        return False
    
    finally:
        await Database.disconnect()


async def main():
    """Run the migration"""
    
    # Check if we need the text import for SQLAlchemy
    try:
        from sqlalchemy import text
        globals()['text'] = text
    except ImportError:
        logger.error("❌ SQLAlchemy text import failed")
        return False
    
    logger.info("🚀 Starting Targets Table Migration")
    logger.info("=" * 50)
    
    # Run migration
    success = await migrate_targets_table()
    
    if success:
        # Verify migration
        verified = await verify_migration()
        
        if verified:
            logger.info("=" * 50)
            logger.info("🎉 MIGRATION COMPLETED SUCCESSFULLY!")
            logger.info("✅ All advanced target fields are now available:")
            logger.info("   - priority (low/medium/high/critical)")
            logger.info("   - max_depth (1-10)")
            logger.info("   - contact_email") 
            logger.info("   - rate_limit (1-100)")
            logger.info("   - authentication_required (boolean)")
            logger.info("   - api_config (JSON)")
            logger.info("   - notes (text)")
            logger.info("\n🚀 You can now restart the backend to use all features!")
            return True
        else:
            logger.error("❌ Migration verification failed")
            return False
    else:
        logger.error("❌ Migration failed")
        return False


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("⚠️ Migration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Migration script failed: {e}")
        sys.exit(1)
