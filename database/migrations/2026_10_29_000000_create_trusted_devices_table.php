<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Olgun\TrustedDevices\Support\Settings;

/**
 * The devices people chose to trust after a two-factor code.
 *
 * - `uuid`: the public address of a trust (the forget route); no integer key
 *   reaches a page.
 * - `user_id`: a string, so integer, UUID and ULID user keys all fit. No foreign
 *   key: the package does not know the host's users table. A trust whose person
 *   is gone signs nobody in.
 * - `token_hash`: the SHA-256 of the secret in the device's cookie. The secret
 *   itself is never stored.
 * - `fingerprint`: an HMAC of the columns in `trusted-devices.fingerprint` when
 *   the trust was made; any of them changing ends the trust.
 * - `signed_out_at`: Log out on that device. It then asks for the password,
 *   not for the code, until the trust ends.
 * - Soft deletes: Forget keeps the row.
 */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        return Settings::connection();
    }

    public function up(): void
    {
        Schema::connection(Settings::connection())->create(Settings::table(), function (Blueprint $table): void {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->string('user_id', 64)->index();
            $table->string('token_hash', 64);
            $table->string('fingerprint', 64);
            $table->string('name', 60);
            $table->string('ip_address', 45)->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('signed_out_at')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });
    }

    public function down(): void
    {
        Schema::connection(Settings::connection())->dropIfExists(Settings::table());
    }
};
